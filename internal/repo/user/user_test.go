package user_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/model"
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

func setupTest(t *testing.T) (*user.Repo, uuid.UUID) {
	t.Helper()
	testDB.Exec("TRUNCATE TABLE iam.users CASCADE")
	appID := uuid.New()
	testDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID, "test-"+appID.String()[:8], "Test App", "test-"+appID.String()[:8], "hash")
	return user.NewRepo(testDB), appID
}

func TestRepo_Create(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	u := &model.User{
		AppID:        appID,
		Email:        "test@example.com",
		PasswordHash: "hash",
		DisplayName:  strPtr("Test User"),
	}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.ID == uuid.Nil {
		t.Error("ID not set after Create")
	}
}

func TestRepo_FindByEmail(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	u := &model.User{
		AppID:        appID,
		Email:        "find@example.com",
		PasswordHash: "hash",
		DisplayName:  strPtr("Find User"),
	}
	repo.Create(ctx, u)

	found, err := repo.FindByEmail(ctx, appID, "find@example.com")
	if err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}
	if found.ID != u.ID {
		t.Errorf("FindByEmail returned wrong user")
	}
}

func TestRepo_FindByEmail_CaseInsensitive(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	u := &model.User{
		AppID:        appID,
		Email:        "Case@Test.COM",
		PasswordHash: "hash",
		DisplayName:  strPtr("Case User"),
	}
	repo.Create(ctx, u)

	found, err := repo.FindByEmail(ctx, appID, "case@test.com")
	if err != nil {
		t.Fatalf("FindByEmail: %v", err)
	}
	if found.ID != u.ID {
		t.Error("case-insensitive lookup failed")
	}
}

func TestRepo_FindByEmail_CrossAppIsolation(t *testing.T) {
	repo, appID1 := setupTest(t)
	ctx := context.Background()

	u := &model.User{
		AppID:        appID1,
		Email:        "shared@example.com",
		PasswordHash: "hash",
		DisplayName:  strPtr("User App1"),
	}
	repo.Create(ctx, u)

	appID2 := uuid.New()
	testDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID2, "test-"+appID2.String()[:8], "Test App 2", "test-"+appID2.String()[:8], "hash")

	_, err := repo.FindByEmail(ctx, appID2, "shared@example.com")
	if err == nil {
		t.Error("FindByEmail found user from different app")
	}
}

func TestRepo_SetEmailVerified(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	u := &model.User{
		AppID:        appID,
		Email:        "verify@example.com",
		PasswordHash: "hash",
		DisplayName:  strPtr("Verify User"),
	}
	repo.Create(ctx, u)

	if err := repo.SetEmailVerified(ctx, appID, u.ID); err != nil {
		t.Fatalf("SetEmailVerified: %v", err)
	}

	found, _ := repo.FindByID(ctx, appID, u.ID)
	if !found.EmailVerified() {
		t.Error("email not marked as verified")
	}
}

func strPtr(s string) *string { return &s }
