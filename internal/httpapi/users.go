package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/ratelimit"
	"github.com/nathan-tsien/iam/internal/service/useradmin"
)

// RegisterUsers mounts /users endpoints on the router.
// Caller must apply Auth + AdminRole middleware to the group.
func RegisterUsers(r *gin.RouterGroup, adminSvc *useradmin.Service, store ratelimit.Store) {
	if store != nil {
		r.GET("/users",
			middleware.RateLimit(store, 100, time.Minute, func(c *gin.Context) string { return rateLimitKey(c, "admin:users") }),
			handleListUsers(adminSvc))
	} else {
		r.GET("/users", handleListUsers(adminSvc))
	}
	r.GET("/users/:id", handleGetUser(adminSvc))
	r.POST("/users/:id/disable", handleDisableUser(adminSvc))
	r.POST("/users/:id/enable", handleEnableUser(adminSvc))
	r.POST("/users/:id/trigger-password-reset", handleTriggerPasswordReset(adminSvc))
}

func handleListUsers(adminSvc *useradmin.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		query := c.Query("q")
		cursor := c.Query("cursor")
		limit := 20
		if raw := c.Query("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 100 {
				limit = parsed
			}
		}

		page, err := adminSvc.ListUsers(c.Request.Context(), app.ID, query, cursor, limit)
		if err != nil {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		items := make([]gin.H, len(page.Items))
		for i := range page.Items {
			items[i] = userToJSON(&page.Items[i])
		}

		c.JSON(http.StatusOK, gin.H{
			"items":       items,
			"next_cursor": page.NextCursor,
			"total":       page.Total,
		})
	}
}

func handleGetUser(adminSvc *useradmin.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		targetID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_ID", "Invalid user ID"))
			return
		}

		u, err := adminSvc.GetUser(c.Request.Context(), app.ID, targetID)
		if err != nil {
			if err == useradmin.ErrUserNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, userToJSON(u))
	}
}

func handleDisableUser(adminSvc *useradmin.Service) gin.HandlerFunc {
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

		targetID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_ID", "Invalid user ID"))
			return
		}

		if err := adminSvc.DisableUser(c.Request.Context(), app.ID, claims.UserID(), targetID); err != nil {
			switch err {
			case useradmin.ErrUserNotFound:
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
			case useradmin.ErrLastAdmin:
				errs.Render(c, errs.New(http.StatusConflict, "LAST_ADMIN", "Cannot disable the last admin"))
			default:
				errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{"disabled": true})
	}
}

func handleEnableUser(adminSvc *useradmin.Service) gin.HandlerFunc {
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

		targetID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_ID", "Invalid user ID"))
			return
		}

		if err := adminSvc.EnableUser(c.Request.Context(), app.ID, claims.UserID(), targetID); err != nil {
			if err == useradmin.ErrUserNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, gin.H{"enabled": true})
	}
}

func handleTriggerPasswordReset(adminSvc *useradmin.Service) gin.HandlerFunc {
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

		targetID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_ID", "Invalid user ID"))
			return
		}

		if err := adminSvc.TriggerPasswordReset(c.Request.Context(), app.ID, claims.UserID(), targetID); err != nil {
			if err == useradmin.ErrUserNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
	}
}
