package refresh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrNotFound = errors.New("refresh token not found, revoked, or expired")

// Token mirrors iam.refresh_tokens.
type Token struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID    uuid.UUID `gorm:"type:uuid;not null"`
	AppID     uuid.UUID `gorm:"type:uuid;not null;index"`
	TokenHash string    `gorm:"not null"`
	IssuedAt  time.Time `gorm:"autoCreateTime"`
	ExpiresAt time.Time `gorm:"not null"`
	RevokedAt *time.Time
}

func (Token) TableName() string { return "refresh_tokens" }

type Repo struct {
	DB *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo { return &Repo{DB: db} }

// Generate issues a new refresh token for userID within an app.
func (r *Repo) Generate(ctx context.Context, appID, userID uuid.UUID, ttl time.Duration) (string, error) {
	plain, err := randomToken()
	if err != nil {
		return "", err
	}
	row := &Token{
		UserID:    userID,
		AppID:     appID,
		TokenHash: hashToken(plain),
		ExpiresAt: time.Now().Add(ttl),
	}
	if err := r.DB.WithContext(ctx).Create(row).Error; err != nil {
		return "", err
	}
	return plain, nil
}

// Lookup finds a valid (not revoked, not expired) token by plaintext value.
func (r *Repo) Lookup(ctx context.Context, plain string) (*Token, error) {
	var row Token
	err := r.DB.WithContext(ctx).
		Where("token_hash = ? AND revoked_at IS NULL AND expires_at > NOW()", hashToken(plain)).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &row, err
}

// Revoke marks the given token revoked.
func (r *Repo) Revoke(ctx context.Context, plain string) error {
	now := time.Now()
	res := r.DB.WithContext(ctx).Model(&Token{}).
		Where("token_hash = ? AND revoked_at IS NULL", hashToken(plain)).
		Update("revoked_at", now)
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return res.Error
}

// Rotate atomically revokes the old token and issues a new one for the same user.
// Replay detection: if the presented token exists but is already revoked,
// revoke every active refresh token for that user.
func (r *Repo) Rotate(ctx context.Context, oldPlain string, ttl time.Duration) (newPlain string, userID uuid.UUID, appID uuid.UUID, err error) {
	var notFound bool
	err = r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var old Token
		if lookupErr := tx.Where(
			"token_hash = ? AND revoked_at IS NULL AND expires_at > NOW()",
			hashToken(oldPlain),
		).First(&old).Error; lookupErr != nil {
			if errors.Is(lookupErr, gorm.ErrRecordNotFound) {
				notFound = true
				// Replay detection
				var revoked Token
				if err := tx.Where("token_hash = ?", hashToken(oldPlain)).First(&revoked).Error; err == nil && revoked.RevokedAt != nil {
					if _, rErr := RevokeAllForUserTx(tx, revoked.UserID); rErr != nil {
						return fmt.Errorf("revoke on replay: %w", rErr)
					}
				}
				return nil
			}
			return lookupErr
		}
		now := time.Now()
		if err := tx.Model(&Token{}).Where("id = ?", old.ID).Update("revoked_at", now).Error; err != nil {
			return err
		}
		userID = old.UserID
		appID = old.AppID
		nPlain, nErr := randomToken()
		if nErr != nil {
			return nErr
		}
		newPlain = nPlain
		return tx.Create(&Token{
			UserID:    old.UserID,
			AppID:     old.AppID,
			TokenHash: hashToken(nPlain),
			ExpiresAt: now.Add(ttl),
		}).Error
	})
	if err == nil && notFound {
		err = ErrNotFound
	}
	return
}

// RevokeAllForUser invalidates every active refresh token for a user.
func (r *Repo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := RevokeAllForUserTx(r.DB.WithContext(ctx), userID)
	return err
}

// RevokeAllForUserTx marks every active refresh token for userID as revoked.
func RevokeAllForUserTx(tx *gorm.DB, userID uuid.UUID) (int64, error) {
	res := tx.Model(&Token{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", time.Now().UTC())
	return res.RowsAffected, res.Error
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}
