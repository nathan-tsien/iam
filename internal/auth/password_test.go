package auth

import "testing"

func TestHashPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	if err := VerifyPassword(hash, "correct horse battery staple"); err != nil {
		t.Errorf("VerifyPassword with correct plaintext: %v", err)
	}
}

func TestVerifyPassword_RejectsWrong(t *testing.T) {
	hash, _ := HashPassword("secret")
	if err := VerifyPassword(hash, "wrong"); err == nil {
		t.Error("VerifyPassword accepted wrong password")
	}
}

func TestHashPassword_DifferentHashesForSameInput(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("bcrypt produced identical hashes; salting likely broken")
	}
}
