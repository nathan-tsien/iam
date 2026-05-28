package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/nathan-tsien/iam/internal/auth"
	"github.com/nathan-tsien/iam/internal/errs"
)

const authClaimsKey = "auth.claims"

// Auth parses a bearer token from the Authorization header and stores the
// verified Claims in the gin context. On any failure it emits 401 and aborts.
func Auth(signer *auth.Signer) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing bearer token"))
			c.Abort()
			return
		}
		token := strings.TrimPrefix(header, prefix)
		claims, err := signer.Verify(token)
		if err != nil {
			errs.Render(c, errs.New(http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired token").WithCause(err))
			c.Abort()
			return
		}
		c.Set(authClaimsKey, claims)
		c.Next()
	}
}

// GetAuthClaims retrieves Claims set by Auth, if any.
func GetAuthClaims(c *gin.Context) (*auth.Claims, bool) {
	v, ok := c.Get(authClaimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*auth.Claims)
	return claims, ok
}
