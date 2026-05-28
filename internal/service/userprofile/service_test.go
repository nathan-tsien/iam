package userprofile_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/model"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/userprofile"
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

func setupTest(t *testing.T) (*userprofile.Service, uuid.UUID) {
	t.Helper()
	testDB.Exec("TRUNCATE TABLE iam.users CASCADE")
	testDB.Exec("TRUNCATE TABLE iam.apps CASCADE")
	appID := uuid.New()
	testDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID, "test-"+appID.String()[:8], "Test App", "test-"+appID.String()[:8], "hash")
	repo := userrepo.NewRepo(testDB)
	svc := userprofile.NewService(userprofile.Deps{UserRepo: repo})
	return svc, appID
}

func createUser(t *testing.T, appID uuid.UUID, email, displayName string) *model.User {
	t.Helper()
	u := &model.User{AppID: appID, Email: email, PasswordHash: "hash", DisplayName: &displayName}
	if err := userrepo.NewRepo(testDB).Create(context.Background(), u); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	return u
}

func TestService_GetProfile(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	u := createUser(t, appID, "gp@example.com", "GP User")

	found, err := svc.GetProfile(ctx, appID, u.ID)
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if found.Email != "gp@example.com" {
		t.Errorf("expected email gp@example.com, got %s", found.Email)
	}
}

func TestService_GetProfile_NotFound(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	_, err := svc.GetProfile(ctx, appID, uuid.New())
	if !errors.Is(err, userrepo.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestService_UpdateProfile_DisplayName(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	u := createUser(t, appID, "up@example.com", "Old Name")

	newName := "New Name"
	updated, err := svc.UpdateProfile(ctx, appID, u.ID, &newName, nil)
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if updated.DisplayName == nil || *updated.DisplayName != "New Name" {
		t.Errorf("display_name not updated, got %v", updated.DisplayName)
	}
}

func TestService_UpdateProfile_AvatarURL(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	u := createUser(t, appID, "av@example.com", "Av User")

	url := "https://cdn.example.com/avatar.jpg"
	updated, err := svc.UpdateProfile(ctx, appID, u.ID, nil, &url)
	if err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if updated.AvatarURL == nil || *updated.AvatarURL != url {
		t.Errorf("avatar_url not updated, got %v", updated.AvatarURL)
	}
}

func TestService_UpdateProfile_DisplayNameTaken(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	createUser(t, appID, "taken@example.com", "Taken Name")
	u2 := createUser(t, appID, "other@example.com", "Other Name")

	newName := "Taken Name"
	_, err := svc.UpdateProfile(ctx, appID, u2.ID, &newName, nil)
	if !errors.Is(err, userrepo.ErrDisplayNameTaken) {
		t.Errorf("expected ErrDisplayNameTaken, got %v", err)
	}
}
