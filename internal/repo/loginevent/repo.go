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

// ListByUser returns login events for a user within an app, paginated by occurred_at cursor.
// Cursor is the occurred_at timestamp of the last item; pass zero time for the first page.
// Returns events and the cursor for the next page (nil if no more).
func (r *Repo) ListByUser(ctx context.Context, userID, appID uuid.UUID, cursor time.Time, limit int) ([]Event, *time.Time, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	q := r.DB.WithContext(ctx).
		Where("user_id = ? AND app_id = ?", userID, appID)

	if !cursor.IsZero() {
		q = q.Where("occurred_at < ?", cursor)
	}

	var events []Event
	err := q.Order("occurred_at DESC").Limit(limit + 1).Find(&events).Error
	if err != nil {
		return nil, nil, err
	}

	var nextCursor *time.Time
	if len(events) > limit {
		nextCursor = &events[limit-1].OccurredAt
		events = events[:limit]
	}

	return events, nextCursor, nil
}
