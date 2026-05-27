package secret

import "testing"

func TestGenerateAndHash(t *testing.T) {
	plain, hash, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if plain == "" || hash == "" {
		t.Fatal("expected non-empty secret and hash")
	}
	if Hash(plain) != hash {
		t.Fatal("hash mismatch")
	}
}
