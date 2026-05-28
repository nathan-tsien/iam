package httpapi

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/ratelimit"
	"github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/auth"
)

// rateLimitKey returns a rate limit key scoped to the current app.
func rateLimitKey(c *gin.Context, suffix string) string {
	app, ok := middleware.GetApp(c)
	if !ok {
		return "unknown:" + suffix
	}
	return app.ID.String() + ":" + suffix
}

// RegisterAuth mounts auth endpoints on the router.
// When store is non-nil, rate limiting is applied to login, register, and
// password-forgot routes.
func RegisterAuth(r *gin.RouterGroup, authSvc *auth.Service, store ratelimit.Store) {
	if store != nil {
		r.POST("/auth/login",
			middleware.RateLimit(store, 5, time.Minute, func(c *gin.Context) string { return rateLimitKey(c, "login") }),
			handleLogin(authSvc))
		r.POST("/auth/register",
			middleware.RateLimit(store, 3, time.Minute, func(c *gin.Context) string { return rateLimitKey(c, "register") }),
			handleRegister(authSvc))
		r.POST("/auth/password/forgot",
			middleware.RateLimit(store, 3, time.Minute, func(c *gin.Context) string { return rateLimitKey(c, "forgot") }),
			handleForgotPassword(authSvc))
	} else {
		r.POST("/auth/login", handleLogin(authSvc))
		r.POST("/auth/register", handleRegister(authSvc))
		r.POST("/auth/password/forgot", handleForgotPassword(authSvc))
	}

	r.POST("/auth/check-availability", handleCheckAvailability(authSvc))
	r.POST("/auth/otp/verify", handleVerifyOTP(authSvc))
	r.POST("/auth/refresh", handleRefresh(authSvc))
	r.POST("/auth/logout", handleLogout(authSvc))
	r.POST("/auth/password/reset", handleResetPassword(authSvc))
}

func handleRegister(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email       string `json:"email" binding:"required"`
			Password    string `json:"password" binding:"required"`
			DisplayName string `json:"display_name" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		resp, err := authSvc.Register(c.Request.Context(), app.ID, req.Email, req.Password, req.DisplayName)
		if err != nil {
			switch e := err.(type) {
			case *auth.ErrWeakPassword:
				errs.Render(c, errs.New(http.StatusBadRequest, "WEAK_PASSWORD", "Password does not meet requirements").
					WithDetails(map[string]any{"failed_rules": e.FailedRules}))
				return
			default:
				if err == user.ErrEmailTaken {
					errs.Render(c, errs.New(http.StatusConflict, "EMAIL_TAKEN", "Email already registered"))
					return
				}
				if err == auth.ErrDisplayNameTaken {
					errs.Render(c, errs.New(http.StatusConflict, "DISPLAY_NAME_TAKEN", "Display name already taken"))
					return
				}
				errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			}
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"user_id":      resp.UserID,
			"email":        resp.Email,
			"display_name": resp.DisplayName,
		})
	}
}

func handleCheckAvailability(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if req.Email == "" && req.DisplayName == "" {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", "At least one of email or display_name is required"))
			return
		}

		resp, err := authSvc.CheckAvailability(c.Request.Context(), app.ID, req.Email, req.DisplayName)
		if err != nil {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

func handleVerifyOTP(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email string `json:"email" binding:"required"`
			Code  string `json:"code" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if err := authSvc.VerifyRegisterOTP(c.Request.Context(), app.ID, req.Email, req.Code); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_OTP", "Invalid or expired OTP code"))
			return
		}

		c.JSON(http.StatusOK, gin.H{"verified": true})
	}
}

func handleLogin(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email    string `json:"email" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		tokens, err := authSvc.Login(c.Request.Context(), app.ID, req.Email, req.Password, app.JWTAudience)
		if err != nil {
			switch err {
			case auth.ErrInvalidCredentials:
				errs.Render(c, errs.New(http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password"))
			case auth.ErrEmailNotVerified:
				errs.Render(c, errs.New(http.StatusForbidden, "EMAIL_NOT_VERIFIED", "Email not verified"))
			case auth.ErrAccountDisabled:
				errs.Render(c, errs.New(http.StatusForbidden, "ACCOUNT_DISABLED", "Account is disabled"))
			default:
				errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"user_id":       tokens.User.ID,
			"email":         tokens.User.Email,
			"role":          tokens.User.Role,
		})
	}
}

func handleRefresh(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		tokens, err := authSvc.Refresh(c.Request.Context(), req.RefreshToken, app.JWTAudience)
		if err != nil {
			if err == auth.ErrInvalidRefresh {
				errs.Render(c, errs.New(http.StatusUnauthorized, "INVALID_REFRESH", "Invalid or expired refresh token"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"user_id":       tokens.User.ID,
			"email":         tokens.User.Email,
			"role":          tokens.User.Role,
		})
	}
}

func handleLogout(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if err := authSvc.Logout(c.Request.Context(), req.RefreshToken); err != nil {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, gin.H{"logged_out": true})
	}
}

func handleForgotPassword(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email string `json:"email" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		// Always return 200 to prevent user enumeration
		_ = authSvc.ForgotPassword(c.Request.Context(), app.ID, req.Email)
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a reset code has been sent"})
	}
}

func handleResetPassword(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email       string `json:"email" binding:"required"`
			Code        string `json:"code" binding:"required"`
			NewPassword string `json:"new_password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if err := authSvc.ResetPassword(c.Request.Context(), app.ID, req.Email, req.Code, req.NewPassword); err != nil {
			switch e := err.(type) {
			case *auth.ErrWeakPassword:
				errs.Render(c, errs.New(http.StatusBadRequest, "WEAK_PASSWORD", "Password does not meet requirements").
					WithDetails(map[string]any{"failed_rules": e.FailedRules}))
			default:
				errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_OTP", "Invalid or expired reset code"))
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
	}
}
