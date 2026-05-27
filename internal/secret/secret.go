package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const tokenBytes = 32

// Generate returns a random URL-safe secret and its SHA-256 hex hash.
func Generate() (plain string, hash string, err error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate secret: %w", err)
	}
	plain = hex.EncodeToString(buf)
	return plain, Hash(plain), nil
}

// Hash returns the SHA-256 hex digest of a secret.
func Hash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
