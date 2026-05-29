package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	pkgauth "github.com/nathan-tsien/iam/internal/auth"
	"github.com/nathan-tsien/iam/internal/auth/passwordpolicy"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/provider/mail"
	"github.com/nathan-tsien/iam/internal/repo/loginevent"
	"github.com/nathan-tsien/iam/internal/repo/refresh"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/otp"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrInvalidRefresh     = errors.New("invalid refresh token")
	ErrAccountDisabled    = errors.New("account disabled")
	ErrDisplayNameTaken   = errors.New("display name already taken")
)

type ErrWeakPassword struct {
	FailedRules []string
}

func (e *ErrWeakPassword) Error() string {
	return "weak password: " + strings.Join(e.FailedRules, ",")
}

type Deps struct {
	UserRepo       *userrepo.Repo
	RefreshRepo    *refresh.Repo
	OTP            *otp.Service
	Signer         *pkgauth.Signer
	RefreshTTL     time.Duration
	LoginEventRepo *loginevent.Repo
}

type Service struct {
	Deps
}

func NewService(d Deps) *Service { return &Service{Deps: d} }

type RegisterResponse struct {
	UserID      uuid.UUID
	Email       string
	DisplayName string
}

// Register creates an unverified user and dispatches a register OTP.
func (s *Service) Register(ctx context.Context, appID uuid.UUID, email, plaintextPassword, displayName string) (*RegisterResponse, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return nil, errors.New("display_name is required")
	}
	if fails := passwordpolicy.Validate(plaintextPassword); len(fails) > 0 {
		return nil, &ErrWeakPassword{FailedRules: fails}
	}
	hash, err := pkgauth.HashPassword(plaintextPassword)
	if err != nil {
		return nil, err
	}

	existing, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil && !errors.Is(err, userrepo.ErrNotFound) {
		return nil, fmt.Errorf("lookup email: %w", err)
	}

	if existing != nil {
		if existing.EmailVerified() {
			return nil, userrepo.ErrEmailTaken
		}
		taken, err := s.UserRepo.DisplayNameExistsExcept(ctx, appID, displayName, existing.ID)
		if err != nil {
			return nil, fmt.Errorf("check display_name: %w", err)
		}
		if taken {
			return nil, ErrDisplayNameTaken
		}
		if err := s.UserRepo.UpdateRegistration(ctx, appID, existing.ID, hash, displayName); err != nil {
			if errors.Is(err, userrepo.ErrDisplayNameTaken) {
				return nil, ErrDisplayNameTaken
			}
			return nil, err
		}
		if err := s.OTP.Issue(ctx, appID, email, mail.PurposeRegister); err != nil {
			return nil, err
		}
		return &RegisterResponse{UserID: existing.ID, Email: email, DisplayName: displayName}, nil
	}

	exists, err := s.UserRepo.DisplayNameExists(ctx, appID, displayName)
	if err != nil {
		return nil, fmt.Errorf("check display_name: %w", err)
	}
	if exists {
		return nil, ErrDisplayNameTaken
	}
	u := &model.User{
		AppID:        appID,
		Email:        email,
		PasswordHash: hash,
		DisplayName:  &displayName,
	}
	if err := s.UserRepo.Create(ctx, u); err != nil {
		return nil, err
	}
	if err := s.OTP.Issue(ctx, appID, email, mail.PurposeRegister); err != nil {
		return nil, err
	}
	return &RegisterResponse{UserID: u.ID, Email: u.Email, DisplayName: displayName}, nil
}

type AvailabilityResult struct {
	EmailAvailable       *bool `json:"email_available"`
	DisplayNameAvailable *bool `json:"display_name_available"`
}

func (s *Service) CheckAvailability(ctx context.Context, appID uuid.UUID, email, displayName string) (*AvailabilityResult, error) {
	res := &AvailabilityResult{}

	if email != "" {
		normalized := strings.ToLower(strings.TrimSpace(email))
		u, err := s.UserRepo.FindByEmail(ctx, appID, normalized)
		switch {
		case err == nil:
			available := !u.EmailVerified()
			res.EmailAvailable = &available
		case errors.Is(err, userrepo.ErrNotFound):
			available := true
			res.EmailAvailable = &available
		default:
			return nil, fmt.Errorf("check email availability: %w", err)
		}
	}

	if displayName != "" {
		exists, err := s.UserRepo.DisplayNameExists(ctx, appID, displayName)
		if err != nil {
			return nil, fmt.Errorf("check display_name availability: %w", err)
		}
		available := !exists
		res.DisplayNameAvailable = &available
	}

	return res, nil
}

// VerifyRegisterOTP consumes a register-purpose code and marks the user verified.
func (s *Service) VerifyRegisterOTP(ctx context.Context, appID uuid.UUID, email, code string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if err := s.OTP.Consume(ctx, appID, email, code, mail.PurposeRegister); err != nil {
		return err
	}
	u, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil {
		return err
	}
	return s.UserRepo.SetEmailVerified(ctx, appID, u.ID)
}

type LoginTokens struct {
	AccessToken  string
	RefreshToken string
	User         *model.User
}

// Login verifies credentials and issues tokens.
func (s *Service) Login(ctx context.Context, appID uuid.UUID, email, plaintextPassword, audience, ip, userAgent string) (*LoginTokens, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			// Record failure event (best-effort)
			if s.LoginEventRepo != nil {
				go func() {
					_ = s.LoginEventRepo.Record(context.Background(), appID, nil, "login_failure", ip, userAgent)
				}()
			}
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if err := pkgauth.VerifyPassword(u.PasswordHash, plaintextPassword); err != nil {
		// Record failure event (best-effort)
		if s.LoginEventRepo != nil {
			go func() {
				_ = s.LoginEventRepo.Record(context.Background(), appID, nil, "login_failure", ip, userAgent)
			}()
		}
		return nil, ErrInvalidCredentials
	}
	if !u.EmailVerified() {
		return nil, ErrEmailNotVerified
	}
	if u.Disabled() {
		return nil, ErrAccountDisabled
	}

	// Record success event (best-effort)
	if s.LoginEventRepo != nil {
		go func() {
			_ = s.LoginEventRepo.Record(context.Background(), appID, &u.ID, "login_success", ip, userAgent)
		}()
	}

	return s.issueTokens(ctx, appID, u, audience)
}

// Refresh rotates a refresh token and issues a new access token.
func (s *Service) Refresh(ctx context.Context, refreshToken, audience string) (*LoginTokens, error) {
	newRefresh, userID, appID, err := s.RefreshRepo.Rotate(ctx, refreshToken, s.RefreshTTL)
	if err != nil {
		return nil, ErrInvalidRefresh
	}
	u, err := s.UserRepo.FindByID(ctx, appID, userID)
	if err != nil {
		return nil, err
	}
	if u.Disabled() {
		return nil, ErrAccountDisabled
	}
	access, err := s.Signer.Sign(u.ID, string(u.Role), audience)
	if err != nil {
		return nil, err
	}
	return &LoginTokens{AccessToken: access, RefreshToken: newRefresh, User: u}, nil
}

// Logout revokes the given refresh token. Idempotent.
func (s *Service) Logout(ctx context.Context, refreshToken, ip, userAgent string) error {
	// Look up token info before revoking (for event recording).
	var eventAppID uuid.UUID
	var eventUserID *uuid.UUID
	if s.LoginEventRepo != nil {
		if tok, err := s.RefreshRepo.Lookup(ctx, refreshToken); err == nil {
			eventAppID = tok.AppID
			eventUserID = &tok.UserID
		}
	}

	err := s.RefreshRepo.Revoke(ctx, refreshToken)
	if errors.Is(err, refresh.ErrNotFound) {
		return nil
	}

	// Record logout event (best-effort)
	if s.LoginEventRepo != nil && eventUserID != nil {
		go func() {
			_ = s.LoginEventRepo.Record(context.Background(), eventAppID, eventUserID, "logout", ip, userAgent)
		}()
	}

	return err
}

// ForgotPassword sends a password reset OTP. Returns nil even if email
// doesn't exist to prevent user enumeration.
func (s *Service) ForgotPassword(ctx context.Context, appID uuid.UUID, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return nil // Don't leak user existence
		}
		return err
	}
	if !u.EmailVerified() {
		return nil // Don't leak unverified status
	}
	// Ignore OTP send errors to prevent enumeration
	_ = s.OTP.Issue(ctx, appID, email, mail.PurposePasswordReset)
	return nil
}

// ResetPassword verifies the reset OTP and sets a new password.
func (s *Service) ResetPassword(ctx context.Context, appID uuid.UUID, email, code, newPassword string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if fails := passwordpolicy.Validate(newPassword); len(fails) > 0 {
		return &ErrWeakPassword{FailedRules: fails}
	}
	if err := s.OTP.Consume(ctx, appID, email, code, mail.PurposePasswordReset); err != nil {
		return err
	}
	u, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil {
		return err
	}
	hash, err := pkgauth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.UserRepo.UpdatePassword(ctx, appID, u.ID, hash); err != nil {
		return err
	}
	// Revoke all refresh tokens after password reset
	return s.RefreshRepo.RevokeAllForUser(ctx, u.ID)
}

func (s *Service) issueTokens(ctx context.Context, appID uuid.UUID, u *model.User, audience string) (*LoginTokens, error) {
	access, err := s.Signer.Sign(u.ID, string(u.Role), audience)
	if err != nil {
		return nil, err
	}
	refreshPlain, err := s.RefreshRepo.Generate(ctx, appID, u.ID, s.RefreshTTL)
	if err != nil {
		return nil, err
	}
	return &LoginTokens{AccessToken: access, RefreshToken: refreshPlain, User: u}, nil
}
