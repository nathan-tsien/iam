package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/repo/loginevent"
	"github.com/nathan-tsien/iam/internal/repo/refresh"
)

var ErrNotFound = errors.New("session not found")

type SessionInfo struct {
	ID          uuid.UUID
	DeviceLabel *string
	UserAgent   string
	IP          string
	CreatedAt   time.Time
	LastSeenAt  *time.Time
	IsCurrent   bool
}

type LoginEvent struct {
	ID         uuid.UUID
	Kind       string
	IP         string
	UserAgent  string
	OccurredAt time.Time
}

type Deps struct {
	RefreshRepo    *refresh.Repo
	LoginEventRepo *loginevent.Repo
}

type Service struct {
	Deps
}

func NewService(d Deps) *Service { return &Service{Deps: d} }

// ListSessions returns active sessions for a user within an app.
// currentTokenHash is the hash of the requesting client's refresh token;
// the matching session gets IsCurrent=true. Pass empty string to skip.
func (s *Service) ListSessions(ctx context.Context, userID, appID uuid.UUID, currentTokenHash string) ([]SessionInfo, error) {
	tokens, err := s.RefreshRepo.ListActive(ctx, userID, appID)
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionInfo, len(tokens))
	for i, t := range tokens {
		sessions[i] = SessionInfo{
			ID:          t.ID,
			DeviceLabel: t.DeviceLabel,
			UserAgent:   t.UserAgent,
			IP:          t.IP,
			CreatedAt:   t.IssuedAt,
			LastSeenAt:  t.LastSeenAt,
			IsCurrent:   currentTokenHash != "" && t.TokenHash == currentTokenHash,
		}
	}

	return sessions, nil
}

// RevokeSession revokes a specific session by ID.
// Returns ErrNotFound if the session doesn't exist or doesn't belong to the user.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	changed, err := s.RefreshRepo.RevokeByID(ctx, sessionID, userID)
	if err != nil {
		return err
	}
	if !changed {
		return ErrNotFound
	}
	return nil
}

// RevokeAllSessions revokes all sessions for a user within an app.
func (s *Service) RevokeAllSessions(ctx context.Context, userID, appID uuid.UUID) error {
	return s.RefreshRepo.RevokeAllForUserInApp(ctx, userID, appID)
}

// LoginHistory returns paginated login events for a user within an app.
func (s *Service) LoginHistory(ctx context.Context, userID, appID uuid.UUID, cursor time.Time, limit int) ([]LoginEvent, *time.Time, error) {
	events, nextCursor, err := s.LoginEventRepo.ListByUser(ctx, userID, appID, cursor, limit)
	if err != nil {
		return nil, nil, err
	}

	result := make([]LoginEvent, len(events))
	for i, e := range events {
		result[i] = LoginEvent{
			ID:         e.ID,
			Kind:       e.Kind,
			IP:         e.IP,
			UserAgent:  e.UserAgent,
			OccurredAt: e.OccurredAt,
		}
	}

	return result, nextCursor, nil
}
