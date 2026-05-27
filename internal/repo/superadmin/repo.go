package superadmin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	apprepo "github.com/nathan-tsien/iam/internal/repo/app"
)

// Model maps to iam.super_admins.
type Model struct {
	UserID    uuid.UUID  `gorm:"type:uuid;primaryKey"`
	GrantedAt time.Time  `gorm:"not null"`
	GrantedBy *uuid.UUID `gorm:"type:uuid"`
}

func (Model) TableName() string {
	return "super_admins"
}

// Repo manages cross-app admin grants.
type Repo struct {
	db *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo {
	return &Repo{db: db}
}

// Grant adds a super-admin grant for a user that belongs to the system app.
func (r *Repo) Grant(ctx context.Context, userID uuid.UUID, grantedBy *uuid.UUID) error {
	systemApp, err := apprepo.NewRepo(r.db).FindBySlug(ctx, apprepo.SystemAppSlug)
	if err != nil {
		return fmt.Errorf("load system app: %w", err)
	}

	var count int64
	if err := r.db.WithContext(ctx).Table("users").
		Where("id = ? AND app_id = ?", userID, systemApp.ID).
		Count(&count).Error; err != nil {
		return fmt.Errorf("verify user app membership: %w", err)
	}
	if count == 0 {
		return errors.New("user must belong to the _iam system app")
	}

	row := Model{
		UserID:    userID,
		GrantedAt: time.Now().UTC(),
		GrantedBy: grantedBy,
	}
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("grant super admin: %w", err)
	}
	return nil
}
