package app

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// Model maps to iam.apps.
type Model struct {
	ID                       uuid.UUID      `gorm:"type:uuid;primaryKey"`
	Slug                     string         `gorm:"not null;uniqueIndex"`
	DisplayName              string         `gorm:"not null"`
	JWTAudience              string         `gorm:"column:jwt_audience;not null;uniqueIndex"`
	HMACSecretHash           string         `gorm:"column:hmac_secret_hash;not null"`
	MailFromName             *string        `gorm:"column:mail_from_name"`
	OAuthRedirectAllowlist   datatypes.JSON `gorm:"column:oauth_redirect_allowlist;type:jsonb;not null;default:'[]'"`
	WebhookURL               *string        `gorm:"column:webhook_url"`
	DisabledAt               *time.Time     `gorm:"column:disabled_at"`
	CreatedAt                time.Time      `gorm:"not null"`
	UpdatedAt                time.Time      `gorm:"not null"`
}

func (Model) TableName() string {
	return "apps"
}

// CreateInput holds validated fields for registering a new app.
type CreateInput struct {
	Slug           string
	DisplayName    string
	JWTAudience    string
	MailFromName   string
	WebhookURL     string
	HMACSecretHash string
}
