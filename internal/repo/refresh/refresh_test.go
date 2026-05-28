package refresh_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/repo/refresh"
	"github.com/nathan-tsien/iam/internal/repo/user"
)

var testDB *gorm.DB

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://localhost:5432/iam_test?sslmode=disable"
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect test database: " + err.Error())
	}
	testDB = db
	os.Exit(m.Run())
}

func setupTest(t *testing.T) (*refresh.Repo, uuid.UUID, uuid.UUID) {
	t.Helper()
	testDB.Exec("TRUNCATE TABLE iam.refresh_tokens CASCADE")
	testDB.Exec("TRUNCATE TABLE iam.users CASCADE")

	appID := uuid.New()
	testDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID, "test-"+appID.String()[:8], "Test App", "test-"+appID.String()[:8], "hash")

	userRepo := user.NewRepo(testDB)
	u := &model.User{
		AppID:        appID,
		Email:        "test@example.com",
		PasswordHash: "hash",
		DisplayName:  strPtr("Test User"),
	}
	userRepo.Create(context.Background(), u)

	return refresh.NewRepo(testDB), appID, u.ID
}

func TestRepo_Generate_Lookup(t *testing.T) {
	repo, appID, userID := setupTest(t)
	ctx := context.Background()

	plain, err := repo.Generate(ctx, appID, userID, 10*time.Minute)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if plain == "" {
		t.Fatal("empty token")
	}

	tok, err := repo.Lookup(ctx, plain)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if tok.UserID != userID {
		t.Errorf("UserID = %v, want %v", tok.UserID, userID)
	}
	if tok.AppID != appID {
		t.Errorf("AppID = %v, want %v", tok.AppID, appID)
	}
}

func TestRepo_Revoke(t *testing.T) {
	repo, appID, userID := setupTest(t)
	ctx := context.Background()

	plain, _ := repo.Generate(ctx, appID, userID, 10*time.Minute)
	if err := repo.Revoke(ctx, plain); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err := repo.Lookup(ctx, plain)
	if err == nil {
		t.Error("Lookup found revoked token")
	}
}

func TestRepo_Rotate(t *testing.T) {
	repo, appID, userID := setupTest(t)
	ctx := context.Background()

	oldPlain, _ := repo.Generate(ctx, appID, userID, 10*time.Minute)
	newPlain, gotUserID, gotAppID, err := repo.Rotate(ctx, oldPlain, 10*time.Minute)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if gotUserID != userID {
		t.Errorf("Rotate returned wrong userID")
	}
	if gotAppID != appID {
		t.Errorf("Rotate returned wrong appID")
	}
	if newPlain == "" {
		t.Fatal("Rotate returned empty token")
	}

	// Old token should be revoked
	_, err = repo.Lookup(ctx, oldPlain)
	if err == nil {
		t.Error("old token still valid after Rotate")
	}

	// New token should be valid
	_, err = repo.Lookup(ctx, newPlain)
	if err != nil {
		t.Errorf("new token invalid after Rotate: %v", err)
	}
}

func strPtr(s string) *string { return &s }
