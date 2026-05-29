package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/model"
)

var (
	ErrNotFound         = errors.New("user not found")
	ErrEmailTaken       = errors.New("email already registered")
	ErrDisplayNameTaken = errors.New("display name already taken")
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

type ListFilter struct {
	AppID  uuid.UUID
	Q      string
	Role   *model.Role
	Status *Status
	Cursor string
	Limit  int
}

type SearchFilter struct {
	AppID uuid.UUID
	Q     string
	Limit int
}

type ListPage struct {
	Items      []model.User
	NextCursor string
	Total      int64
}

type Repo struct {
	DB *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo { return &Repo{DB: db} }

// Create inserts a new user. Email is lower-cased for uniqueness.
func (r *Repo) Create(ctx context.Context, u *model.User) error {
	u.Email = strings.ToLower(u.Email)
	u.EmailLower = u.Email
	err := r.DB.WithContext(ctx).Create(u).Error
	if err != nil && isUniqueViolation(err) {
		return ErrEmailTaken
	}
	return err
}

// FindByEmail returns the user with the given email within an app, or ErrNotFound.
func (r *Repo) FindByEmail(ctx context.Context, appID uuid.UUID, email string) (*model.User, error) {
	var u model.User
	err := r.DB.WithContext(ctx).
		Where("app_id = ? AND email_lower = ?", appID, strings.ToLower(email)).
		First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &u, err
}

// FindByID returns the user with the given id within an app, or ErrNotFound.
func (r *Repo) FindByID(ctx context.Context, appID, id uuid.UUID) (*model.User, error) {
	var u model.User
	err := r.DB.WithContext(ctx).
		Where("app_id = ? AND id = ?", appID, id).
		First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &u, err
}

// SetEmailVerified marks the user's email as verified.
func (r *Repo) SetEmailVerified(ctx context.Context, appID, id uuid.UUID) error {
	res := r.DB.WithContext(ctx).Model(&model.User{}).
		Where("app_id = ? AND id = ?", appID, id).
		Updates(map[string]any{
			"email_verified_at": gorm.Expr("NOW()"),
			"updated_at":        gorm.Expr("NOW()"),
		})
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return res.Error
}

// UpdatePassword sets a new password_hash for the given user.
func (r *Repo) UpdatePassword(ctx context.Context, appID, id uuid.UUID, hash string) error {
	res := r.DB.WithContext(ctx).Model(&model.User{}).
		Where("app_id = ? AND id = ?", appID, id).
		Updates(map[string]any{
			"password_hash": hash,
			"updated_at":    gorm.Expr("NOW()"),
		})
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return res.Error
}

// DisplayNameExists reports whether a user with the given display_name exists in the app.
func (r *Repo) DisplayNameExists(ctx context.Context, appID uuid.UUID, name string) (bool, error) {
	var count int64
	err := r.DB.WithContext(ctx).
		Model(&model.User{}).
		Where("app_id = ? AND display_name = ?", appID, name).
		Count(&count).Error
	return count > 0, err
}

// DisplayNameExistsExcept reports whether a user other than exceptID owns
// the given display_name in the app.
func (r *Repo) DisplayNameExistsExcept(ctx context.Context, appID uuid.UUID, name string, exceptID uuid.UUID) (bool, error) {
	var count int64
	err := r.DB.WithContext(ctx).
		Model(&model.User{}).
		Where("app_id = ? AND display_name = ? AND id <> ?", appID, name, exceptID).
		Count(&count).Error
	return count > 0, err
}

// UpdateRegistration overwrites password_hash and display_name.
func (r *Repo) UpdateRegistration(ctx context.Context, appID, id uuid.UUID, hash, displayName string) error {
	res := r.DB.WithContext(ctx).Model(&model.User{}).
		Where("app_id = ? AND id = ?", appID, id).
		Updates(map[string]any{
			"password_hash": hash,
			"display_name":  displayName,
			"updated_at":    gorm.Expr("NOW()"),
		})
	if res.Error != nil {
		if isUniqueViolation(res.Error) {
			return ErrDisplayNameTaken
		}
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDisabledAtTx flips users.disabled_at within an outer tx.
func SetDisabledAtTx(tx *gorm.DB, appID, id uuid.UUID, at *time.Time) (changed bool, err error) {
	var where string
	if at != nil {
		where = "app_id = ? AND id = ? AND disabled_at IS NULL"
	} else {
		where = "app_id = ? AND id = ? AND disabled_at IS NOT NULL"
	}
	res := tx.Model(&model.User{}).Where(where, appID, id).Update("disabled_at", at)
	return res.RowsAffected == 1, res.Error
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate key value") || strings.Contains(msg, "SQLSTATE 23505")
}

func uniqueViolationConstraint(err error) string {
	msg := err.Error()
	const marker = `unique constraint "`
	if i := strings.Index(msg, marker); i >= 0 {
		start := i + len(marker)
		if end := strings.Index(msg[start:], `"`); end >= 0 {
			return msg[start : start+end]
		}
	}
	return ""
}

// UpdateProfile patches display_name and/or avatar_url for the given user.
// Nil fields are skipped.
func (r *Repo) UpdateProfile(ctx context.Context, appID, id uuid.UUID, displayName, avatarURL *string) error {
	updates := map[string]any{
		"updated_at": gorm.Expr("NOW()"),
	}
	if displayName != nil {
		updates["display_name"] = *displayName
	}
	if avatarURL != nil {
		updates["avatar_url"] = *avatarURL
	}
	res := r.DB.WithContext(ctx).Model(&model.User{}).
		Where("app_id = ? AND id = ?", appID, id).
		Updates(updates)
	if res.Error != nil {
		if displayName != nil && isUniqueViolation(res.Error) {
			return ErrDisplayNameTaken
		}
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// CountActiveAdmins returns the number of non-disabled admin users in the app.
func (r *Repo) CountActiveAdmins(ctx context.Context, appID uuid.UUID) (int64, error) {
	var count int64
	err := r.DB.WithContext(ctx).
		Model(&model.User{}).
		Where("app_id = ? AND role = 'admin' AND disabled_at IS NULL", appID).
		Count(&count).Error
	return count, err
}

// List returns paginated users with optional search query.
// When query is non-empty, matches against email_lower and display_name (ILIKE).
// Cursor is the ID of the last item from the previous page; empty for the first page.
func (r *Repo) List(ctx context.Context, filter ListFilter) (*ListPage, error) {
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 20
	}

	q := r.DB.WithContext(ctx).Model(&model.User{}).Where("app_id = ?", filter.AppID)

	if filter.Q != "" {
		like := "%" + filter.Q + "%"
		q = q.Where("(email_lower ILIKE ? OR display_name ILIKE ?)", like, like)
	}
	if filter.Role != nil {
		q = q.Where("role = ?", string(*filter.Role))
	}
	if filter.Status != nil {
		switch *filter.Status {
		case StatusActive:
			q = q.Where("disabled_at IS NULL")
		case StatusDisabled:
			q = q.Where("disabled_at IS NOT NULL")
		}
	}

	// Count total before pagination.
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, err
	}

	// Cursor pagination: fetch items after the cursor.
	if filter.Cursor != "" {
		cursorID, err := uuid.Parse(filter.Cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}
		q = q.Where("id > ?", cursorID)
	}

	q = q.Order("created_at ASC, id ASC").Limit(filter.Limit + 1)

	var users []model.User
	if err := q.Find(&users).Error; err != nil {
		return nil, err
	}

	page := &ListPage{
		Items: users,
		Total: total,
	}

	if len(users) > filter.Limit {
		page.Items = users[:filter.Limit]
		page.NextCursor = users[filter.Limit].ID.String()
	}

	return page, nil
}
