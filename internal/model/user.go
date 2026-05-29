package model

import (
	"time"

	"github.com/google/uuid"
)

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// User mirrors iam.users. Business fields (tier, agent_memory_paused) are excluded.
type User struct {
	ID              uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	AppID           uuid.UUID  `gorm:"type:uuid;not null;index"`
	Email           string     `gorm:"not null"`
	EmailLower      string     `gorm:"column:email_lower;not null"`
	PasswordHash    string     `gorm:"not null"`
	Role            Role       `gorm:"type:text;not null;default:'user'"`
	DisplayName     *string    `gorm:"type:varchar(100)"`
	AvatarURL       *string    `gorm:"type:text"`
	EmailVerifiedAt *time.Time
	DisabledAt      *time.Time
	DeletedAt       *time.Time
	CreatedAt       time.Time  `gorm:"autoCreateTime"`
	UpdatedAt       time.Time  `gorm:"autoUpdateTime"`
}

func (User) TableName() string { return "users" }

func (u *User) EmailVerified() bool { return u.EmailVerifiedAt != nil }
func (u *User) Disabled() bool      { return u.DisabledAt != nil }
func (u *User) Deleted() bool       { return u.DeletedAt != nil }

func (u *User) ApplicantName() string {
	if u.DisplayName != nil && *u.DisplayName != "" {
		return *u.DisplayName
	}
	return u.Email
}
