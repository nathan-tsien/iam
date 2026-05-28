package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/repo/app"
)

const appKey = "app"

// AppSlugMiddleware resolves {slug} from the URL path to an app.Model.
// Rejects disabled apps with 403.
func AppSlugMiddleware(appRepo *app.Repo) gin.HandlerFunc {
	return func(c *gin.Context) {
		slug := c.Param("slug")
		if slug == "" {
			errs.Render(c, errs.New(http.StatusBadRequest, "MISSING_SLUG", "App slug is required"))
			c.Abort()
			return
		}

		a, err := appRepo.FindBySlug(c.Request.Context(), slug)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "APP_NOT_FOUND", "App not found"))
				c.Abort()
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error"))
			c.Abort()
			return
		}

		if a.DisabledAt != nil {
			errs.Render(c, errs.New(http.StatusForbidden, "APP_DISABLED", "App is disabled"))
			c.Abort()
			return
		}

		c.Set(appKey, a)
		c.Next()
	}
}

// GetApp retrieves the app.Model set by AppSlugMiddleware.
func GetApp(c *gin.Context) (*app.Model, bool) {
	v, ok := c.Get(appKey)
	if !ok {
		return nil, false
	}
	a, ok := v.(*app.Model)
	return a, ok
}
