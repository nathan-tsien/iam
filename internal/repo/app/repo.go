package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}[a-z0-9]$`)

// Repo persists app registry rows.
type Repo struct {
	db *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo {
	return &Repo{db: db}
}

// ValidateSlug checks slug format rules.
func ValidateSlug(slug string) error {
	if slug == "_iam" {
		return fmt.Errorf("slug %q is reserved", slug)
	}
	if !slugPattern.MatchString(slug) {
		return fmt.Errorf("slug %q must match %s", slug, slugPattern.String())
	}
	return nil
}

// Create inserts a new app row.
func (r *Repo) Create(ctx context.Context, in CreateInput) (Model, error) {
	if err := ValidateSlug(in.Slug); err != nil {
		return Model{}, err
	}
	if strings.TrimSpace(in.DisplayName) == "" {
		return Model{}, errors.New("display name is required")
	}
	if in.JWTAudience == "" {
		in.JWTAudience = in.Slug
	}
	if in.HMACSecretHash == "" {
		return Model{}, errors.New("hmac secret hash is required")
	}

	now := time.Now().UTC()
	row := Model{
		ID:             uuid.New(),
		Slug:           in.Slug,
		DisplayName:    strings.TrimSpace(in.DisplayName),
		JWTAudience:    in.JWTAudience,
		HMACSecretHash: in.HMACSecretHash,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if in.MailFromName != "" {
		row.MailFromName = &in.MailFromName
	}
	if in.WebhookURL != "" {
		row.WebhookURL = &in.WebhookURL
	}

	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		return Model{}, fmt.Errorf("create app: %w", err)
	}
	return row, nil
}

// List returns all apps ordered by slug.
func (r *Repo) List(ctx context.Context) ([]Model, error) {
	var rows []Model
	if err := r.db.WithContext(ctx).Order("slug ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	return rows, nil
}

// Disable soft-disables an app by slug.
func (r *Repo) Disable(ctx context.Context, slug string) error {
	now := time.Now().UTC()
	result := r.db.WithContext(ctx).Model(&Model{}).
		Where("slug = ? AND disabled_at IS NULL", slug).
		Updates(map[string]any{
			"disabled_at": now,
			"updated_at":  now,
		})
	if result.Error != nil {
		return fmt.Errorf("disable app: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("app %q not found or already disabled", slug)
	}
	return nil
}

// FindBySlug returns the app with the given slug, or gorm.ErrRecordNotFound.
func (r *Repo) FindBySlug(ctx context.Context, slug string) (*Model, error) {
	var m Model
	err := r.db.WithContext(ctx).Where("slug = ?", slug).First(&m).Error
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// SystemAppSlug is the reserved slug for super-admin operators.
const SystemAppSlug = "_iam"
