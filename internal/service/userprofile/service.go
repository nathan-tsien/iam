package userprofile

import (
	"context"
	"errors"

	"github.com/google/uuid"

	pkgauth "github.com/nathan-tsien/iam/internal/auth"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/repo/auditlog"
	"github.com/nathan-tsien/iam/internal/repo/refresh"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
)

var ErrInvalidPassword = errors.New("invalid password")

type Deps struct {
	UserRepo    *userrepo.Repo
	RefreshRepo *refresh.Repo
	AuditRepo   *auditlog.Repo
}

type Service struct {
	Deps
}

func NewService(d Deps) *Service { return &Service{Deps: d} }

// GetProfile returns the user's profile by ID within an app.
func (s *Service) GetProfile(ctx context.Context, appID, userID uuid.UUID) (*model.User, error) {
	u, err := s.UserRepo.FindByID(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return nil, userrepo.ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// UpdateProfile patches display_name and/or avatar_url.
// Nil fields are left unchanged.
func (s *Service) UpdateProfile(ctx context.Context, appID, userID uuid.UUID, displayName, avatarURL *string) (*model.User, error) {
	if err := s.UserRepo.UpdateProfile(ctx, appID, userID, displayName, avatarURL); err != nil {
		return nil, err
	}
	return s.UserRepo.FindByID(ctx, appID, userID)
}

// DeleteAccount soft-deletes the user, anonymizes PII, and revokes all sessions.
// Verifies password before proceeding. Returns ErrInvalidPassword on mismatch.
func (s *Service) DeleteAccount(ctx context.Context, appID, userID uuid.UUID, password string) error {
	u, err := s.UserRepo.FindByID(ctx, appID, userID)
	if err != nil {
		return err
	}

	if err := pkgauth.VerifyPassword(u.PasswordHash, password); err != nil {
		return ErrInvalidPassword
	}

	if err := s.UserRepo.SoftDelete(ctx, appID, userID); err != nil {
		return err
	}

	// Revoke all sessions
	_ = s.RefreshRepo.RevokeAllForUserInApp(ctx, userID, appID)

	// Write audit log (best-effort)
	if s.AuditRepo != nil {
		go func() {
			_ = s.AuditRepo.Record(context.Background(), &auditlog.Entry{
				AppID:    appID,
				ActorID:  &userID,
				TargetID: &userID,
				Action:   "user.deleted",
			})
		}()
	}

	return nil
}
