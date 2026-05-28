package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/model"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
)

const adminUserKey = "admin.user"

// AdminRole verifies the authenticated user still has admin role in the DB.
// Must be placed after Auth and AppSlugMiddleware.
func AdminRole(userRepo *userrepo.Repo) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := GetAuthClaims(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing auth claims"))
			c.Abort()
			return
		}

		app, ok := GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			c.Abort()
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			errs.Render(c, errs.New(http.StatusUnauthorized, "INVALID_TOKEN", "Invalid subject claim"))
			c.Abort()
			return
		}

		u, err := userRepo.FindByID(c.Request.Context(), app.ID, userID)
		if err != nil {
			errs.Render(c, errs.New(http.StatusUnauthorized, "USER_NOT_FOUND", "User not found"))
			c.Abort()
			return
		}

		if u.Disabled() {
			errs.Render(c, errs.New(http.StatusForbidden, "ACCOUNT_DISABLED", "Account is disabled"))
			c.Abort()
			return
		}

		if u.Role != model.RoleAdmin {
			errs.Render(c, errs.New(http.StatusForbidden, "FORBIDDEN", "Admin access required"))
			c.Abort()
			return
		}

		c.Set(adminUserKey, u)
		c.Next()
	}
}

// GetAdminUser retrieves the model.User verified by AdminRole middleware.
func GetAdminUser(c *gin.Context) (*model.User, bool) {
	v, ok := c.Get(adminUserKey)
	if !ok {
		return nil, false
	}
	u, ok := v.(*model.User)
	return u, ok
}
