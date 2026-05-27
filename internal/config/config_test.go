package config

import (
	"testing"
)

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when DATABASE_URL is empty")
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/iam?sslmode=disable")
	t.Setenv("APP_PORT", "")
	t.Setenv("DATABASE_SCHEMA", "")
	t.Setenv("APP_ENV", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.AppPort != 8090 {
		t.Fatalf("AppPort = %d, want 8090", cfg.AppPort)
	}
	if cfg.DatabaseSchema != "iam" {
		t.Fatalf("DatabaseSchema = %q, want iam", cfg.DatabaseSchema)
	}
	if cfg.AppEnv != "development" {
		t.Fatalf("AppEnv = %q, want development", cfg.AppEnv)
	}
}
