package useradmin

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/provider/mail"
	"github.com/nathan-tsien/iam/internal/repo/auditlog"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/otp"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrLastAdmin    = errors.New("cannot disable the last admin")
)

type Deps struct {
	UserRepo  *userrepo.Repo
	AuditRepo *auditlog.Repo
	OTP       *otp.Service
}

type Service struct {
	Deps
}

func NewService(d Deps) *Service { return &Service{Deps: d} }

// ListUsers returns paginated users with optional search keyword.
func (s *Service) ListUsers(ctx context.Context, appID uuid.UUID, query string, cursor string, limit int) (*userrepo.ListPage, error) {
	return s.UserRepo.List(ctx, userrepo.ListFilter{
		AppID:  appID,
		Q:      query,
		Cursor: cursor,
		Limit:  limit,
	})
}

// GetUser returns a single user by ID within the app.
func (s *Service) GetUser(ctx context.Context, appID, userID uuid.UUID) (*model.User, error) {
	u, err := s.UserRepo.FindByID(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return u, nil
}

// DisableUser sets disabled_at. Rejects if target is the last active admin.
func (s *Service) DisableUser(ctx context.Context, appID, actorID, targetID uuid.UUID) error {
	target, err := s.UserRepo.FindByID(ctx, appID, targetID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	// Last admin protection.
	if target.Role == model.RoleAdmin && target.DisabledAt == nil {
		count, err := s.UserRepo.CountActiveAdmins(ctx, appID)
		if err != nil {
			return err
		}
		if count <= 1 {
			return ErrLastAdmin
		}
	}

	now := time.Now()
	changed, err := userrepo.SetDisabledAtTx(s.UserRepo.DB.WithContext(ctx), appID, targetID, &now)
	if err != nil {
		return err
	}

	if changed {
		s.writeAudit(ctx, appID, actorID, targetID, "user.disabled", target.Email)
	}

	return nil
}

// EnableUser clears disabled_at. Idempotent.
func (s *Service) EnableUser(ctx context.Context, appID, actorID, targetID uuid.UUID) error {
	target, err := s.UserRepo.FindByID(ctx, appID, targetID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	changed, err := userrepo.SetDisabledAtTx(s.UserRepo.DB.WithContext(ctx), appID, targetID, nil)
	if err != nil {
		return err
	}

	if changed {
		s.writeAudit(ctx, appID, actorID, targetID, "user.enabled", target.Email)
	}

	return nil
}

// TriggerPasswordReset sends a password reset OTP to the target user.
func (s *Service) TriggerPasswordReset(ctx context.Context, appID, actorID, targetID uuid.UUID) error {
	target, err := s.UserRepo.FindByID(ctx, appID, targetID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	if err := s.OTP.Issue(ctx, appID, target.Email, mail.PurposePasswordReset); err != nil {
		return err
	}

	s.writeAudit(ctx, appID, actorID, targetID, "user.password_reset_triggered", target.Email)

	return nil
}

func (s *Service) writeAudit(ctx context.Context, appID, actorID, targetID uuid.UUID, action, targetEmail string) {
	if s.AuditRepo == nil {
		return
	}
	entry := &auditlog.Entry{
		AppID:    appID,
		ActorID:  &actorID,
		TargetID: &targetID,
		Action:   action,
		Metadata: auditlog.JSONB{"target_email": targetEmail},
	}
	if err := s.AuditRepo.Record(ctx, entry); err != nil {
		slog.Error("write audit log", "action", action, "error", err)
	}
}
