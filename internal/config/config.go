package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds process configuration loaded from the environment.
type Config struct {
	AppEnv         string
	AppPort        int
	DatabaseURL    string
	DatabaseSchema string
	JWTSecret      string
	JWTTTL         time.Duration
	RefreshTTL     time.Duration
	SMTPHost       string
	SMTPPort       int
	SMTPUsername   string
	SMTPPassword   string
	SMTPFromAddr   string
	SMTPFromName   string
}

// Load reads configuration from environment variables.
func Load() (Config, error) {
	port := 8090
	if raw := os.Getenv("APP_PORT"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse APP_PORT: %w", err)
		}
		port = parsed
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}

	schema := os.Getenv("DATABASE_SCHEMA")
	if schema == "" {
		schema = "iam"
	}

	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return Config{}, fmt.Errorf("JWT_SECRET is required (min 32 bytes)")
	}
	if len(jwtSecret) < 32 {
		return Config{}, fmt.Errorf("JWT_SECRET must be at least 32 bytes, got %d", len(jwtSecret))
	}

	jwtTTL := 15 * time.Minute
	if raw := os.Getenv("JWT_TTL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse JWT_TTL: %w", err)
		}
		jwtTTL = d
	}

	refreshTTL := 720 * time.Hour // 30 days
	if raw := os.Getenv("REFRESH_TTL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse REFRESH_TTL: %w", err)
		}
		refreshTTL = d
	}

	smtpPort := 465
	if raw := os.Getenv("SMTP_PORT"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse SMTP_PORT: %w", err)
		}
		smtpPort = parsed
	}

	return Config{
		AppEnv:         env,
		AppPort:        port,
		DatabaseURL:    databaseURL,
		DatabaseSchema: schema,
		JWTSecret:      jwtSecret,
		JWTTTL:         jwtTTL,
		RefreshTTL:     refreshTTL,
		SMTPHost:       os.Getenv("SMTP_HOST"),
		SMTPPort:       smtpPort,
		SMTPUsername:   os.Getenv("SMTP_USERNAME"),
		SMTPPassword:   os.Getenv("SMTP_PASSWORD"),
		SMTPFromAddr:   os.Getenv("SMTP_FROM_ADDR"),
		SMTPFromName:   os.Getenv("SMTP_FROM_NAME"),
	}, nil
}
