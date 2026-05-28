package auditlog_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/repo/auditlog"
)

var testDB *gorm.DB

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/iam_test?sslmode=disable"
	}
	if !strings.Contains(dsn, "search_path=") {
		sep := "?"
		if strings.Contains(dsn, "?") {
			sep = "&"
		}
		dsn = dsn + sep + "search_path=iam"
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect test database: " + err.Error())
	}
	testDB = db
	os.Exit(m.Run())
}

func setupTest(t *testing.T) (*auditlog.Repo, uuid.UUID) {
	t.Helper()
	testDB.Exec("TRUNCATE TABLE iam.audit_logs CASCADE")
	testDB.Exec("TRUNCATE TABLE iam.users CASCADE")
	testDB.Exec("TRUNCATE TABLE iam.apps CASCADE")
	appID := uuid.New()
	testDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID, "test-"+appID.String()[:8], "Test App", "test-"+appID.String()[:8], "hash")
	return auditlog.NewRepo(testDB), appID
}

func createTestUser(t *testing.T, appID uuid.UUID) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	email := "user-" + userID.String()[:8] + "@example.com"
	testDB.Exec("INSERT INTO iam.users (id, app_id, email, email_lower, role) VALUES (?, ?, ?, ?, ?)",
		userID, appID, email, email, "user")
	return userID
}

func TestRepo_Record(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	actorID := createTestUser(t, appID)
	targetID := createTestUser(t, appID)
	entry := &auditlog.Entry{
		AppID:    appID,
		ActorID:  &actorID,
		TargetID: &targetID,
		Action:   "user.disabled",
		Metadata: auditlog.JSONB{"target_email": "test@example.com"},
	}

	if err := repo.Record(ctx, entry); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if entry.ID == uuid.Nil {
		t.Error("ID not set after Record")
	}
}
