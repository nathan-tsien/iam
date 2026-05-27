package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the JWT payload carried by access tokens.
type Claims struct {
	Role     string `json:"role"`
	Audience string `json:"aud"`
	jwt.RegisteredClaims
}

// Signer signs and verifies access tokens using HS256.
type Signer struct {
	secret []byte
	ttl    time.Duration
}

const minSecretBytes = 32

func NewSigner(secret string, ttl time.Duration) *Signer {
	if len(secret) < minSecretBytes {
		panic(fmt.Sprintf("auth.NewSigner: secret must be at least %d bytes, got %d", minSecretBytes, len(secret)))
	}
	return &Signer{secret: []byte(secret), ttl: ttl}
}

// Sign issues a new token for the given user with the role and audience embedded.
func (s *Signer) Sign(userID uuid.UUID, role, audience string) (string, error) {
	now := time.Now()
	claims := Claims{
		Role:     role,
		Audience: audience,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(s.secret)
}

// Verify parses and validates a token string, returning the claims on success.
func (s *Signer) Verify(tokenStr string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
