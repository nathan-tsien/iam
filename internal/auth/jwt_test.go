package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	return NewSigner("this-secret-is-exactly-32-bytes!", 5*time.Minute)
}

func TestSigner_SignVerify_RoundTrip(t *testing.T) {
	s := newTestSigner(t)
	uid := uuid.New()

	token, err := s.Sign(uid, "user", "demo")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}

	claims, err := s.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != uid.String() {
		t.Errorf("Subject = %q, want %q", claims.Subject, uid.String())
	}
	if claims.Role != "user" {
		t.Errorf("Role = %q, want user", claims.Role)
	}
	if claims.Audience != "demo" {
		t.Errorf("Audience = %q, want demo", claims.Audience)
	}
	if claims.ID == "" {
		t.Error("JTI empty")
	}
}

func TestSigner_Verify_RejectsTamperedToken(t *testing.T) {
	s := newTestSigner(t)
	token, _ := s.Sign(uuid.New(), "user", "demo")
	// Flip bits in the middle of the payload to guarantee signature mismatch.
	b := []byte(token)
	// Find second dot (start of payload) and corrupt a byte in the payload.
	dotCount := 0
	for i, c := range b {
		if c == '.' {
			dotCount++
			if dotCount == 2 {
				// i is the second dot; flip a byte in the payload (just before it).
				b[i-1] ^= 0xFF
				break
			}
		}
	}
	if _, err := s.Verify(string(b)); err == nil {
		t.Error("Verify accepted tampered token")
	}
}

func TestSigner_Verify_RejectsExpiredToken(t *testing.T) {
	s := NewSigner("this-secret-is-exactly-32-bytes!", -1*time.Second)
	token, _ := s.Sign(uuid.New(), "user", "demo")
	if _, err := s.Verify(token); err == nil {
		t.Error("Verify accepted expired token")
	}
}

func TestSigner_Verify_RejectsMalformed(t *testing.T) {
	s := newTestSigner(t)
	for _, in := range []string{"", "not-a-jwt", "a.b.c"} {
		if _, err := s.Verify(in); err == nil {
			t.Errorf("Verify(%q) accepted", in)
		}
	}
}

func TestNewSigner_PanicsOnShortSecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewSigner did not panic on short secret")
		}
	}()
	_ = NewSigner("too-short", time.Minute)
}

func TestSigner_Verify_RejectsWrongSecret(t *testing.T) {
	a := NewSigner("this-secret-is-exactly-32-bytes!", 5*time.Minute)
	b := NewSigner("another-secret-that-is-32-bytes!", 5*time.Minute)
	token, _ := a.Sign(uuid.New(), "user", "demo")
	if _, err := b.Verify(token); err == nil {
		t.Error("Verify accepted token signed with different secret")
	}
}
