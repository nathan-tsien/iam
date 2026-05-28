package loginevent

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Event mirrors iam.login_events.
type Event struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID     *uuid.UUID `gorm:"type:uuid"`
	AppID      uuid.UUID  `gorm:"type:uuid;not null"`
	Kind       string     `gorm:"not null"`
	IP         string
	UserAgent  string
	OccurredAt time.Time  `gorm:"autoCreateTime"`
}

func (Event) TableName() string { return "login_events" }

type Repo struct {
	DB *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo { return &Repo{DB: db} }

// Record inserts a login event. Best-effort — callers should not fail on error.
func (r *Repo) Record(ctx context.Context, appID uuid.UUID, userID *uuid.UUID, kind, ip, userAgent string) error {
	e := &Event{
		UserID:    userID,
		AppID:     appID,
		Kind:      kind,
		IP:        ip,
		UserAgent: userAgent,
	}
	return r.DB.WithContext(ctx).Create(e).Error
}
