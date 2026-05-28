package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/userprofile"
)

// RegisterMe mounts /me endpoints on the router.
// Caller must apply Auth middleware to the group.
func RegisterMe(r *gin.RouterGroup, profileSvc *userprofile.Service) {
	r.GET("/me", handleGetMe(profileSvc))
	r.PATCH("/me", handleUpdateMe(profileSvc))
}

func handleGetMe(profileSvc *userprofile.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}
		claims, ok := middleware.GetAuthClaims(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing auth claims"))
			return
		}

		profile, err := profileSvc.GetProfile(c.Request.Context(), app.ID, claims.UserID())
		if err != nil {
			if err == user.ErrNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, userToJSON(profile))
	}
}

func handleUpdateMe(profileSvc *userprofile.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}
		claims, ok := middleware.GetAuthClaims(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing auth claims"))
			return
		}

		var req struct {
			DisplayName *string `json:"display_name"`
			AvatarURL   *string `json:"avatar_url"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if req.DisplayName == nil && req.AvatarURL == nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", "At least one of display_name or avatar_url is required"))
			return
		}

		profile, err := profileSvc.UpdateProfile(c.Request.Context(), app.ID, claims.UserID(), req.DisplayName, req.AvatarURL)
		if err != nil {
			if err == user.ErrDisplayNameTaken {
				errs.Render(c, errs.New(http.StatusConflict, "DISPLAY_NAME_TAKEN", "Display name already taken"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, userToJSON(profile))
	}
}

func userToJSON(u *model.User) gin.H {
	h := gin.H{
		"id":         u.ID,
		"app_id":     u.AppID,
		"email":      u.Email,
		"role":       u.Role,
		"created_at": u.CreatedAt,
		"updated_at": u.UpdatedAt,
	}
	if u.DisplayName != nil {
		h["display_name"] = *u.DisplayName
	}
	if u.AvatarURL != nil {
		h["avatar_url"] = *u.AvatarURL
	}
	if u.EmailVerifiedAt != nil {
		h["email_verified_at"] = *u.EmailVerifiedAt
	}
	if u.DisabledAt != nil {
		h["disabled_at"] = *u.DisabledAt
	}
	return h
}
