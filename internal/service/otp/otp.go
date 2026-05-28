package otp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/provider/mail"
)

const (
	CodeLength = 6
	DefaultTTL = 10 * time.Minute
)

var (
	ErrNotFound     = errors.New("no active OTP found")
	ErrCodeMismatch = errors.New("OTP code does not match")
)

// Code mirrors iam.otp_codes.
type Code struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	AppID      uuid.UUID `gorm:"type:uuid;not null;index"`
	Email      string    `gorm:"column:email_lower;not null"`
	CodeHash   string    `gorm:"not null"`
	Purpose    string    `gorm:"type:text;not null"`
	ExpiresAt  time.Time `gorm:"not null"`
	ConsumedAt *time.Time
	CreatedAt  time.Time `gorm:"autoCreateTime"`
}

func (Code) TableName() string { return "otp_codes" }

type Service struct {
	DB        *gorm.DB
	Mailer    mail.Mailer
	TTL       time.Duration
	FixedCode string
	Logger    *slog.Logger
	IsProd    bool
}

func NewService(db *gorm.DB, mailer mail.Mailer, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Service{DB: db, Mailer: mailer, TTL: ttl}
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// Issue generates a new 6-digit code, stores its SHA-256 hash with expiry,
// and dispatches the plaintext via the Mailer.
func (s *Service) Issue(ctx context.Context, appID uuid.UUID, email string, purpose mail.Purpose) error {
	var code string
	if s.FixedCode != "" {
		code = s.FixedCode
		s.logger().Warn("dev fixed OTP in use",
			"email", email,
			"purpose", string(purpose))
	} else {
		random, err := randomDigits(CodeLength)
		if err != nil {
			return fmt.Errorf("generate code: %w", err)
		}
		code = random
	}
	now := time.Now()
	row := &Code{
		AppID:     appID,
		Email:     email,
		CodeHash:  hashCode(code),
		Purpose:   string(purpose),
		ExpiresAt: now.Add(s.TTL),
	}
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Code{}).
			Where("app_id = ? AND email_lower = ? AND purpose = ? AND consumed_at IS NULL",
				appID, email, string(purpose)).
			Update("consumed_at", now).Error; err != nil {
			return fmt.Errorf("invalidate prior otps: %w", err)
		}
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("persist code: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	locale := mail.LocaleFrom(ctx)
	if !s.IsProd {
		s.logger().InfoContext(ctx, "dev-aid: OTP code issued",
			"email", email,
			"purpose", string(purpose),
			"code", code,
			"locale", string(locale),
		)
	}
	return s.Mailer.SendOTP(ctx, email, code, purpose, locale)
}

// Consume verifies the code for email+purpose and marks it consumed.
func (s *Service) Consume(ctx context.Context, appID uuid.UUID, email, code string, purpose mail.Purpose) error {
	var row Code
	err := s.DB.WithContext(ctx).
		Where("app_id = ? AND email_lower = ? AND purpose = ? AND consumed_at IS NULL AND expires_at > NOW()",
			appID, email, string(purpose)).
		Order("created_at DESC").
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if row.CodeHash != hashCode(code) {
		return ErrCodeMismatch
	}
	now := time.Now()
	return s.DB.WithContext(ctx).Model(&Code{}).
		Where("id = ?", row.ID).
		Update("consumed_at", now).Error
}

func randomDigits(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	digits := make([]byte, n)
	for i := range buf {
		digits[i] = '0' + (buf[i] % 10)
	}
	return string(digits), nil
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}
