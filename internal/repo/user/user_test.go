package user_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

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

func TestRepo_UpdateProfile_DisplayName(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	u := &model.User{AppID: appID, Email: "up@example.com", PasswordHash: "hash", DisplayName: strPtr("Old")}
	repo.Create(ctx, u)

	newName := "New Name"
	if err := repo.UpdateProfile(ctx, appID, u.ID, &newName, nil); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}

	found, _ := repo.FindByID(ctx, appID, u.ID)
	if found.DisplayName == nil || *found.DisplayName != "New Name" {
		t.Errorf("display_name not updated, got %v", found.DisplayName)
	}
}

func TestRepo_UpdateProfile_AvatarURL(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	u := &model.User{AppID: appID, Email: "av@example.com", PasswordHash: "hash", DisplayName: strPtr("Av")}
	repo.Create(ctx, u)

	url := "https://cdn.example.com/avatar.jpg"
	if err := repo.UpdateProfile(ctx, appID, u.ID, nil, &url); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}

	found, _ := repo.FindByID(ctx, appID, u.ID)
	if found.AvatarURL == nil || *found.AvatarURL != url {
		t.Errorf("avatar_url not updated, got %v", found.AvatarURL)
	}
}

func TestRepo_UpdateProfile_DisplayNameTaken(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	u1 := &model.User{AppID: appID, Email: "u1@example.com", PasswordHash: "hash", DisplayName: strPtr("Taken")}
	repo.Create(ctx, u1)
	u2 := &model.User{AppID: appID, Email: "u2@example.com", PasswordHash: "hash", DisplayName: strPtr("Other")}
	repo.Create(ctx, u2)

	newName := "Taken"
	err := repo.UpdateProfile(ctx, appID, u2.ID, &newName, nil)
	if err != user.ErrDisplayNameTaken {
		t.Fatalf("expected ErrDisplayNameTaken, got %v", err)
	}
}

func TestRepo_CountActiveAdmins(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	now := time.Now()
	admin1 := &model.User{AppID: appID, Email: "a1@example.com", PasswordHash: "hash", Role: model.RoleAdmin, DisplayName: strPtr("A1")}
	admin2 := &model.User{AppID: appID, Email: "a2@example.com", PasswordHash: "hash", Role: model.RoleAdmin, DisplayName: strPtr("A2")}
	adminDisabled := &model.User{AppID: appID, Email: "ad@example.com", PasswordHash: "hash", Role: model.RoleAdmin, DisplayName: strPtr("AD"), DisabledAt: &now}
	regular := &model.User{AppID: appID, Email: "r1@example.com", PasswordHash: "hash", DisplayName: strPtr("R1")}
	repo.Create(ctx, admin1)
	repo.Create(ctx, admin2)
	repo.Create(ctx, adminDisabled)
	repo.Create(ctx, regular)

	count, err := repo.CountActiveAdmins(ctx, appID)
	if err != nil {
		t.Fatalf("CountActiveAdmins: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 active admins, got %d", count)
	}
}

func TestRepo_List_Pagination(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		u := &model.User{AppID: appID, Email: fmt.Sprintf("list%d@example.com", i), PasswordHash: "hash", DisplayName: strPtr(fmt.Sprintf("User %d", i))}
		repo.Create(ctx, u)
	}

	page1, err := repo.List(ctx, user.ListFilter{AppID: appID, Limit: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page1.Items) != 2 {
		t.Errorf("expected 2 items, got %d", len(page1.Items))
	}
	if page1.Total != 5 {
		t.Errorf("expected total 5, got %d", page1.Total)
	}
	if page1.NextCursor == "" {
		t.Error("expected next_cursor for page 1")
	}

	page2, err := repo.List(ctx, user.ListFilter{AppID: appID, Limit: 2, Cursor: page1.NextCursor})
	if err != nil {
		t.Fatalf("List page 2: %v", err)
	}
	if len(page2.Items) != 2 {
		t.Errorf("expected 2 items on page 2, got %d", len(page2.Items))
	}
}

func TestRepo_List_Search(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	repo.Create(ctx, &model.User{AppID: appID, Email: "alice@example.com", PasswordHash: "hash", DisplayName: strPtr("Alice")})
	repo.Create(ctx, &model.User{AppID: appID, Email: "bob@example.com", PasswordHash: "hash", DisplayName: strPtr("Bob")})

	page, err := repo.List(ctx, user.ListFilter{AppID: appID, Q: "alice"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Items) != 1 {
		t.Errorf("expected 1 result for 'alice', got %d", len(page.Items))
	}
	if page.Items[0].Email != "alice@example.com" {
		t.Errorf("expected alice, got %s", page.Items[0].Email)
	}
}
