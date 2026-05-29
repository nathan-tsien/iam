package httpapi

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	openapi_types "github.com/oapi-codegen/runtime/types"

	api "github.com/nathan-tsien/iam/api"
	authpkg "github.com/nathan-tsien/iam/internal/auth"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/ratelimit"
	"github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/auth"
	"github.com/nathan-tsien/iam/internal/service/useradmin"
	"github.com/nathan-tsien/iam/internal/service/userprofile"
)

// StrictServer implements api.StrictServerInterface, bridging generated
// request/response types to the domain services.
type StrictServer struct {
	AuthSvc    *auth.Service
	ProfileSvc *userprofile.Service
	AdminSvc   *useradmin.Service
}

// --- Auth endpoints ---

func (s *StrictServer) CheckAvailability(ctx context.Context, request api.CheckAvailabilityRequestObject) (api.CheckAvailabilityResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}

	var email, displayName string
	if request.Body.Email != nil {
		email = string(*request.Body.Email)
	}
	if request.Body.DisplayName != nil {
		displayName = *request.Body.DisplayName
	}

	if email == "" && displayName == "" {
		return api.CheckAvailability400JSONResponse{
			BadRequestJSONResponse: api.BadRequestJSONResponse{
				Code:    "INVALID_REQUEST",
				Message: "At least one of email or display_name is required",
			},
		}, nil
	}

	resp, err := s.AuthSvc.CheckAvailability(ctx, app.ID, email, displayName)
	if err != nil {
		return nil, err
	}

	return api.CheckAvailability200JSONResponse{
		EmailAvailable:       resp.EmailAvailable,
		DisplayNameAvailable: resp.DisplayNameAvailable,
	}, nil
}

func (s *StrictServer) Login(ctx context.Context, request api.LoginRequestObject) (api.LoginResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}

	tokens, err := s.AuthSvc.Login(
		ctx, app.ID,
		string(request.Body.Email), request.Body.Password,
		app.JWTAudience, "", "",
	)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			return api.Login401JSONResponse{
				Code:    "INVALID_CREDENTIALS",
				Message: "Invalid email or password",
			}, nil
		case errors.Is(err, auth.ErrEmailNotVerified):
			return api.Login403JSONResponse{
				Code:    "EMAIL_NOT_VERIFIED",
				Message: "Email not verified",
			}, nil
		case errors.Is(err, auth.ErrAccountDisabled):
			return api.Login403JSONResponse{
				Code:    "ACCOUNT_DISABLED",
				Message: "Account is disabled",
			}, nil
		default:
			return nil, err
		}
	}

	return api.Login200JSONResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		UserId:       openapi_types.UUID(tokens.User.ID),
		Email:        tokens.User.Email,
		Role:         api.TokenResponseRole(tokens.User.Role),
	}, nil
}

func (s *StrictServer) Logout(ctx context.Context, request api.LogoutRequestObject) (api.LogoutResponseObject, error) {
	// Logout is idempotent; always return success.
	_ = s.AuthSvc.Logout(ctx, request.Body.RefreshToken, "", "")

	return api.Logout200JSONResponse{
		LoggedOut: api.LogoutResponseLoggedOutTrue,
	}, nil
}

func (s *StrictServer) VerifyOTP(ctx context.Context, request api.VerifyOTPRequestObject) (api.VerifyOTPResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}

	if err := s.AuthSvc.VerifyRegisterOTP(ctx, app.ID, string(request.Body.Email), request.Body.Code); err != nil {
		return api.VerifyOTP400JSONResponse{
			BadRequestJSONResponse: api.BadRequestJSONResponse{
				Code:    "INVALID_OTP",
				Message: "Invalid or expired OTP code",
			},
		}, nil
	}

	return api.VerifyOTP200JSONResponse{
		Verified: api.VerifyOTPResponseVerifiedTrue,
	}, nil
}

func (s *StrictServer) ForgotPassword(ctx context.Context, request api.ForgotPasswordRequestObject) (api.ForgotPasswordResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}

	// Always return success to prevent user enumeration.
	_ = s.AuthSvc.ForgotPassword(ctx, app.ID, string(request.Body.Email))

	return api.ForgotPassword200JSONResponse{
		Message: "If the email exists, a reset code has been sent",
	}, nil
}

func (s *StrictServer) ResetPassword(ctx context.Context, request api.ResetPasswordRequestObject) (api.ResetPasswordResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}

	err := s.AuthSvc.ResetPassword(
		ctx, app.ID,
		string(request.Body.Email), request.Body.Code, request.Body.NewPassword,
	)
	if err != nil {
		var weakPwd *auth.ErrWeakPassword
		if errors.As(err, &weakPwd) {
			return api.ResetPassword400JSONResponse{
				BadRequestJSONResponse: api.BadRequestJSONResponse{
					Code:    "WEAK_PASSWORD",
					Message: "Password does not meet requirements",
					Details: ptrMap(map[string]interface{}{"failed_rules": weakPwd.FailedRules}),
				},
			}, nil
		}
		return api.ResetPassword400JSONResponse{
			BadRequestJSONResponse: api.BadRequestJSONResponse{
				Code:    "INVALID_OTP",
				Message: "Invalid or expired reset code",
			},
		}, nil
	}

	return api.ResetPassword200JSONResponse{
		Message: "Password reset successfully",
	}, nil
}

func (s *StrictServer) RefreshToken(ctx context.Context, request api.RefreshTokenRequestObject) (api.RefreshTokenResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}

	tokens, err := s.AuthSvc.Refresh(ctx, request.Body.RefreshToken, app.JWTAudience)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidRefresh):
			return api.RefreshToken401JSONResponse{
				Code:    "INVALID_REFRESH",
				Message: "Invalid or expired refresh token",
			}, nil
		case errors.Is(err, auth.ErrAccountDisabled):
			return api.RefreshToken403JSONResponse{
				Code:    "ACCOUNT_DISABLED",
				Message: "Account is disabled",
			}, nil
		default:
			return nil, err
		}
	}

	return api.RefreshToken200JSONResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		UserId:       openapi_types.UUID(tokens.User.ID),
		Email:        tokens.User.Email,
		Role:         api.TokenResponseRole(tokens.User.Role),
	}, nil
}

func (s *StrictServer) Register(ctx context.Context, request api.RegisterRequestObject) (api.RegisterResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}

	resp, err := s.AuthSvc.Register(
		ctx, app.ID,
		string(request.Body.Email), request.Body.Password, request.Body.DisplayName,
	)
	if err != nil {
		var weakPwd *auth.ErrWeakPassword
		switch {
		case errors.As(err, &weakPwd):
			return api.Register400JSONResponse{
				BadRequestJSONResponse: api.BadRequestJSONResponse{
					Code:    "WEAK_PASSWORD",
					Message: "Password does not meet requirements",
					Details: ptrMap(map[string]interface{}{"failed_rules": weakPwd.FailedRules}),
				},
			}, nil
		case errors.Is(err, user.ErrEmailTaken):
			return api.Register409JSONResponse{
				Code:    "EMAIL_TAKEN",
				Message: "Email already registered",
			}, nil
		case errors.Is(err, auth.ErrDisplayNameTaken):
			return api.Register409JSONResponse{
				Code:    "DISPLAY_NAME_TAKEN",
				Message: "Display name already taken",
			}, nil
		default:
			return nil, err
		}
	}

	return api.Register201JSONResponse{
		UserId:      openapi_types.UUID(resp.UserID),
		Email:       resp.Email,
		DisplayName: resp.DisplayName,
	}, nil
}

// --- Self-service endpoints (auth required) ---

func (s *StrictServer) GetMe(ctx context.Context, request api.GetMeRequestObject) (api.GetMeResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}
	claims, ok := middleware.GetAuthClaims(gc)
	if !ok {
		return nil, errors.New("auth claims not in context")
	}

	profile, err := s.ProfileSvc.GetProfile(ctx, app.ID, claims.UserID())
	if err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return api.GetMe404JSONResponse{
				NotFoundJSONResponse: api.NotFoundJSONResponse{
					Code:    "USER_NOT_FOUND",
					Message: "User not found",
				},
			}, nil
		}
		return nil, err
	}

	return api.GetMe200JSONResponse(userToAPI(profile)), nil
}

func (s *StrictServer) UpdateMe(ctx context.Context, request api.UpdateMeRequestObject) (api.UpdateMeResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}
	claims, ok := middleware.GetAuthClaims(gc)
	if !ok {
		return nil, errors.New("auth claims not in context")
	}

	if request.Body.DisplayName == nil && request.Body.AvatarUrl == nil {
		return api.UpdateMe400JSONResponse{
			BadRequestJSONResponse: api.BadRequestJSONResponse{
				Code:    "INVALID_REQUEST",
				Message: "At least one of display_name or avatar_url is required",
			},
		}, nil
	}

	profile, err := s.ProfileSvc.UpdateProfile(
		ctx, app.ID, claims.UserID(),
		request.Body.DisplayName, request.Body.AvatarUrl,
	)
	if err != nil {
		if errors.Is(err, user.ErrDisplayNameTaken) {
			return api.UpdateMe409JSONResponse{
				Code:    "DISPLAY_NAME_TAKEN",
				Message: "Display name already taken",
			}, nil
		}
		return nil, err
	}

	return api.UpdateMe200JSONResponse(userToAPI(profile)), nil
}

// --- Admin endpoints (auth + admin role required) ---

func (s *StrictServer) ListUsers(ctx context.Context, request api.ListUsersRequestObject) (api.ListUsersResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}

	var query, cursor string
	limit := 20

	if request.Params.Q != nil {
		query = *request.Params.Q
	}
	if request.Params.Cursor != nil {
		cursor = *request.Params.Cursor
	}
	if request.Params.Limit != nil && *request.Params.Limit > 0 && *request.Params.Limit <= 100 {
		limit = *request.Params.Limit
	}

	page, err := s.AdminSvc.ListUsers(ctx, app.ID, query, cursor, limit)
	if err != nil {
		return nil, err
	}

	items := make([]api.User, len(page.Items))
	for i := range page.Items {
		items[i] = userToAPI(&page.Items[i])
	}

	return api.ListUsers200JSONResponse{
		Items:      items,
		NextCursor: page.NextCursor,
		Total:      int(page.Total),
	}, nil
}

func (s *StrictServer) GetUser(ctx context.Context, request api.GetUserRequestObject) (api.GetUserResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}

	u, err := s.AdminSvc.GetUser(ctx, app.ID, request.Id)
	if err != nil {
		if errors.Is(err, useradmin.ErrUserNotFound) {
			return api.GetUser404JSONResponse{
				NotFoundJSONResponse: api.NotFoundJSONResponse{
					Code:    "USER_NOT_FOUND",
					Message: "User not found",
				},
			}, nil
		}
		return nil, err
	}

	return api.GetUser200JSONResponse(userToAPI(u)), nil
}

func (s *StrictServer) DisableUser(ctx context.Context, request api.DisableUserRequestObject) (api.DisableUserResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}
	adminUser, ok := middleware.GetAdminUser(gc)
	if !ok {
		return nil, errors.New("admin user not in context")
	}

	if err := s.AdminSvc.DisableUser(ctx, app.ID, adminUser.ID, request.Id); err != nil {
		switch {
		case errors.Is(err, useradmin.ErrUserNotFound):
			return api.DisableUser404JSONResponse{
				NotFoundJSONResponse: api.NotFoundJSONResponse{
					Code:    "USER_NOT_FOUND",
					Message: "User not found",
				},
			}, nil
		case errors.Is(err, useradmin.ErrLastAdmin):
			return api.DisableUser409JSONResponse{
				Code:    "LAST_ADMIN",
				Message: "Cannot disable the last admin",
			}, nil
		default:
			return nil, err
		}
	}

	return api.DisableUser200JSONResponse{
		Disabled: api.DisabledResponseDisabledTrue,
	}, nil
}

func (s *StrictServer) EnableUser(ctx context.Context, request api.EnableUserRequestObject) (api.EnableUserResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}
	adminUser, ok := middleware.GetAdminUser(gc)
	if !ok {
		return nil, errors.New("admin user not in context")
	}

	if err := s.AdminSvc.EnableUser(ctx, app.ID, adminUser.ID, request.Id); err != nil {
		if errors.Is(err, useradmin.ErrUserNotFound) {
			return api.EnableUser404JSONResponse{
				NotFoundJSONResponse: api.NotFoundJSONResponse{
					Code:    "USER_NOT_FOUND",
					Message: "User not found",
				},
			}, nil
		}
		return nil, err
	}

	return api.EnableUser200JSONResponse{
		Enabled: api.EnabledResponseEnabledTrue,
	}, nil
}

func (s *StrictServer) TriggerPasswordReset(ctx context.Context, request api.TriggerPasswordResetRequestObject) (api.TriggerPasswordResetResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}
	adminUser, ok := middleware.GetAdminUser(gc)
	if !ok {
		return nil, errors.New("admin user not in context")
	}

	if err := s.AdminSvc.TriggerPasswordReset(ctx, app.ID, adminUser.ID, request.Id); err != nil {
		if errors.Is(err, useradmin.ErrUserNotFound) {
			return api.TriggerPasswordReset404JSONResponse{
				NotFoundJSONResponse: api.NotFoundJSONResponse{
					Code:    "USER_NOT_FOUND",
					Message: "User not found",
				},
			}, nil
		}
		return nil, err
	}

	return api.TriggerPasswordReset200JSONResponse{
		Message: "Password reset email sent",
	}, nil
}

// --- Helpers ---

// userToAPI converts a domain User to the API User type.
func userToAPI(u *model.User) api.User {
	apiUser := api.User{
		Id:          openapi_types.UUID(u.ID),
		AppId:       openapi_types.UUID(u.AppID),
		Email:       u.Email,
		Role:        api.UserRole(u.Role),
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		DisplayName: u.DisplayName,
		AvatarUrl:   u.AvatarURL,
	}
	if u.EmailVerifiedAt != nil {
		apiUser.EmailVerifiedAt = u.EmailVerifiedAt
	}
	if u.DisabledAt != nil {
		apiUser.DisabledAt = u.DisabledAt
	}
	return apiUser
}

// ptrMap wraps a map in a pointer for use with Error.Details.
func ptrMap(m map[string]interface{}) *map[string]interface{} {
	return &m
}

// --- Strict middleware ---

// AppError is returned by strict middleware to signal HTTP errors.
type AppError struct {
	Status  int
	Code    string
	Message string
}

func (e *AppError) Error() string { return e.Message }

// Operations that require authentication.
var authRequiredOps = map[string]bool{
	"GetMe":                true,
	"UpdateMe":             true,
	"ListUsers":            true,
	"GetUser":              true,
	"DisableUser":          true,
	"EnableUser":           true,
	"TriggerPasswordReset": true,
}

// Operations that require admin role (subset of auth-required).
var adminRequiredOps = map[string]bool{
	"ListUsers":            true,
	"GetUser":              true,
	"DisableUser":          true,
	"EnableUser":           true,
	"TriggerPasswordReset": true,
}

// Rate limit config per operation.
var rateLimitOps = map[string]struct {
	Max    int64
	Window time.Duration
}{
	"Register":       {Max: 3, Window: time.Minute},
	"Login":          {Max: 5, Window: time.Minute},
	"ForgotPassword": {Max: 3, Window: time.Minute},
	"ListUsers":      {Max: 100, Window: time.Minute},
}

// StrictAuthMiddleware verifies the bearer token for auth-required operations.
func StrictAuthMiddleware(signer *authpkg.Signer) api.StrictMiddlewareFunc {
	return func(f api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
		if !authRequiredOps[operationID] {
			return f
		}
		return func(ctx *gin.Context, request any) (any, error) {
			header := ctx.GetHeader("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(header, prefix) {
				return nil, &AppError{Status: 401, Code: "UNAUTHENTICATED", Message: "Missing bearer token"}
			}
			token := strings.TrimPrefix(header, prefix)
			claims, err := signer.Verify(token)
			if err != nil {
				return nil, &AppError{Status: 401, Code: "INVALID_TOKEN", Message: "Invalid or expired token"}
			}
			ctx.Set("auth.claims", claims)
			return f(ctx, request)
		}
	}
}

// StrictAdminMiddleware verifies admin role for admin-required operations.
func StrictAdminMiddleware(userRepo *user.Repo) api.StrictMiddlewareFunc {
	return func(f api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
		if !adminRequiredOps[operationID] {
			return f
		}
		return func(ctx *gin.Context, request any) (any, error) {
			claims, ok := middleware.GetAuthClaims(ctx)
			if !ok {
				return nil, &AppError{Status: 401, Code: "UNAUTHENTICATED", Message: "Missing auth claims"}
			}
			app, ok := middleware.GetApp(ctx)
			if !ok {
				return nil, &AppError{Status: 500, Code: "INTERNAL", Message: "App not in context"}
			}
			u, err := userRepo.FindByID(ctx.Request.Context(), app.ID, claims.UserID())
			if err != nil {
				return nil, &AppError{Status: 401, Code: "USER_NOT_FOUND", Message: "User not found"}
			}
			if u.Disabled() {
				return nil, &AppError{Status: 403, Code: "ACCOUNT_DISABLED", Message: "Account is disabled"}
			}
			if u.Role != model.RoleAdmin {
				return nil, &AppError{Status: 403, Code: "FORBIDDEN", Message: "Admin access required"}
			}
			ctx.Set("admin.user", u)
			return f(ctx, request)
		}
	}
}

// StrictRateLimitMiddleware applies per-operation rate limiting.
func StrictRateLimitMiddleware(store ratelimit.Store) api.StrictMiddlewareFunc {
	return func(f api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
		cfg, ok := rateLimitOps[operationID]
		if !ok || store == nil {
			return f
		}
		return func(ctx *gin.Context, request any) (any, error) {
			app, _ := middleware.GetApp(ctx)
			key := app.ID.String() + ":" + operationID
			allowed, _, err := ratelimit.Allow(ctx.Request.Context(), store, key, cfg.Max, cfg.Window)
			if err != nil {
				return f(ctx, request) // fail open
			}
			if !allowed {
				return nil, &AppError{Status: 429, Code: "RATE_LIMITED", Message: "Too many requests"}
			}
			return f(ctx, request)
		}
	}
}

// Ensure StrictServer implements api.StrictServerInterface at compile time.
var _ api.StrictServerInterface = (*StrictServer)(nil)
