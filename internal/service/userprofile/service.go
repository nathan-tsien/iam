package userprofile

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/model"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
)

type Deps struct {
	UserRepo *userrepo.Repo
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
