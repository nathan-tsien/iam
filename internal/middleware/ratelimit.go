package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/ratelimit"
)

// RateLimit returns middleware that limits requests using the given store.
func RateLimit(store ratelimit.Store, max int64, window time.Duration, keyFunc func(c *gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := keyFunc(c)
		allowed, remaining, err := ratelimit.Allow(c.Request.Context(), store, key, max, window)
		if err != nil {
			// On error, allow the request (fail open)
			c.Next()
			return
		}
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", max))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		if !allowed {
			errs.Render(c, errs.New(http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests"))
			c.Abort()
			return
		}
		c.Next()
	}
}
