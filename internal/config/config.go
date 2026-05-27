package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds process configuration loaded from the environment.
type Config struct {
	AppEnv         string
	AppPort        int
	DatabaseURL    string
	DatabaseSchema string
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

	return Config{
		AppEnv:         env,
		AppPort:        port,
		DatabaseURL:    databaseURL,
		DatabaseSchema: schema,
	}, nil
}
