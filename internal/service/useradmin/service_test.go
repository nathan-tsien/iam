package useradmin_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/provider/mail"
	"github.com/nathan-tsien/iam/internal/repo/auditlog"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/otp"
	"github.com/nathan-tsien/iam/internal/service/useradmin"
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

func setupTest(t *testing.T) (*useradmin.Service, uuid.UUID) {
	t.Helper()
	testDB.Exec("TRUNCATE TABLE iam.users CASCADE")
	testDB.Exec("TRUNCATE TABLE iam.audit_logs CASCADE")
	testDB.Exec("TRUNCATE TABLE iam.apps CASCADE")
	appID := uuid.New()
	testDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID, "test-"+appID.String()[:8], "Test App", "test-"+appID.String()[:8], "hash")
	userRepo := userrepo.NewRepo(testDB)
	auditRepo := auditlog.NewRepo(testDB)
	otpSvc := otp.NewService(testDB, &nopMailer{}, 10*time.Minute)
	svc := useradmin.NewService(useradmin.Deps{
		UserRepo:  userRepo,
		AuditRepo: auditRepo,
		OTP:       otpSvc,
	})
	return svc, appID
}

type nopMailer struct{}

func (nopMailer) SendOTP(_ context.Context, _, _ string, _ mail.Purpose, _ mail.Locale) error { return nil }

func createUser(t *testing.T, appID uuid.UUID, email string, role model.Role) *model.User {
	t.Helper()
	u := &model.User{AppID: appID, Email: email, PasswordHash: "hash", Role: role, DisplayName: &email}
	if err := userrepo.NewRepo(testDB).Create(context.Background(), u); err != nil {
		t.Fatalf("createUser: %v", err)
	}
	return u
}

func strPtr(s string) *string { return &s }

func TestService_DisableUser_HappyPath(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	actor := createUser(t, appID, "actor@example.com", model.RoleAdmin)
	target := createUser(t, appID, "target@example.com", model.RoleUser)

	if err := svc.DisableUser(ctx, appID, actor.ID, target.ID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}

	found, _ := userrepo.NewRepo(testDB).FindByID(ctx, appID, target.ID)
	if !found.Disabled() {
		t.Error("user should be disabled")
	}
}

func TestService_DisableUser_LastAdmin(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	admin := createUser(t, appID, "sole-admin@example.com", model.RoleAdmin)

	err := svc.DisableUser(ctx, appID, admin.ID, admin.ID)
	if !errors.Is(err, useradmin.ErrLastAdmin) {
		t.Errorf("expected ErrLastAdmin, got %v", err)
	}
}

func TestService_DisableUser_NotFound(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	actor := createUser(t, appID, "actor@example.com", model.RoleAdmin)

	err := svc.DisableUser(ctx, appID, actor.ID, uuid.New())
	if !errors.Is(err, useradmin.ErrUserNotFound) {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestService_EnableUser_HappyPath(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	actor := createUser(t, appID, "actor@example.com", model.RoleAdmin)
	now := time.Now()
	target := &model.User{AppID: appID, Email: "disabled@example.com", PasswordHash: "hash", Role: model.RoleUser, DisplayName: strPtr("Disabled"), DisabledAt: &now}
	userrepo.NewRepo(testDB).Create(ctx, target)

	if err := svc.EnableUser(ctx, appID, actor.ID, target.ID); err != nil {
		t.Fatalf("EnableUser: %v", err)
	}

	found, _ := userrepo.NewRepo(testDB).FindByID(ctx, appID, target.ID)
	if found.Disabled() {
		t.Error("user should be enabled")
	}
}

func TestService_EnableUser_Idempotent(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	actor := createUser(t, appID, "actor@example.com", model.RoleAdmin)
	target := createUser(t, appID, "active@example.com", model.RoleUser)

	// Already enabled — should not error.
	if err := svc.EnableUser(ctx, appID, actor.ID, target.ID); err != nil {
		t.Fatalf("EnableUser idempotent: %v", err)
	}
}

func TestService_ListUsers(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	for i := range 3 {
		createUser(t, appID, "user"+string(rune('a'+i))+"@example.com", model.RoleUser)
	}

	page, err := svc.ListUsers(ctx, appID, "", "", 10)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if page.Total != 3 {
		t.Errorf("expected 3 users, got %d", page.Total)
	}
}

func TestService_TriggerPasswordReset(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	actor := createUser(t, appID, "actor@example.com", model.RoleAdmin)
	target := createUser(t, appID, "target@example.com", model.RoleUser)

	if err := svc.TriggerPasswordReset(ctx, appID, actor.ID, target.ID); err != nil {
		t.Fatalf("TriggerPasswordReset: %v", err)
	}
}
