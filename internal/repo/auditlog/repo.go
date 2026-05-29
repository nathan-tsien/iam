package auditlog

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Entry mirrors iam.audit_logs.
type Entry struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	AppID     uuid.UUID  `gorm:"type:uuid;not null"`
	ActorID   *uuid.UUID `gorm:"type:uuid"`
	TargetID  *uuid.UUID `gorm:"type:uuid"`
	Action    string     `gorm:"not null"`
	Metadata  JSONB      `gorm:"type:jsonb;not null;default:'{}'::jsonb"`
	CreatedAt time.Time  `gorm:"autoCreateTime"`
}

func (Entry) TableName() string { return "audit_logs" }

// JSONB is a map that GORM serializes to JSONB.
type JSONB map[string]any

// Value implements the driver.Valuer interface for JSONB.
func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

// Scan implements the sql.Scanner interface for JSONB.
func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("auditlog.JSONB.Scan: expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, j)
}

type Repo struct {
	DB *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo { return &Repo{DB: db} }

// Record inserts an audit log entry.
func (r *Repo) Record(ctx context.Context, entry *Entry) error {
	return r.DB.WithContext(ctx).Create(entry).Error
}
