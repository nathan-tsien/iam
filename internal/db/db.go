package db

import (
	"fmt"
	"net/url"
	"strings"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open connects to Postgres with the configured schema search_path.
func Open(databaseURL, schema string, appEnv string) (*gorm.DB, error) {
	dsn, err := withSearchPath(databaseURL, schema)
	if err != nil {
		return nil, err
	}

	logLevel := logger.Warn
	if appEnv == "development" {
		logLevel = logger.Info
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("database handle: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return db, nil
}

func withSearchPath(databaseURL, schema string) (string, error) {
	if strings.Contains(databaseURL, "search_path=") {
		return databaseURL, nil
	}
	sep := "?"
	if strings.Contains(databaseURL, "?") {
		sep = "&"
	}
	return databaseURL + sep + "search_path=" + url.QueryEscape(schema), nil
}
