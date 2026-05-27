package otp_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/provider/mail"
	"github.com/nathan-tsien/iam/internal/service/otp"
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

type mockMailer struct {
	sent []string
}

func (m *mockMailer) SendOTP(_ context.Context, email, code string, _ mail.Purpose, _ mail.Locale) error {
	m.sent = append(m.sent, code)
	return nil
}

func setupTest(t *testing.T) (*otp.Service, uuid.UUID) {
	t.Helper()
	testDB.Exec("TRUNCATE TABLE iam.otp_codes CASCADE")
	appID := uuid.New()
	testDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID, "test-"+appID.String()[:8], "Test App", "test-"+appID.String()[:8], "hash")
	mailer := &mockMailer{}
	svc := otp.NewService(testDB, mailer, 10*time.Minute)
	return svc, appID
}

func TestService_Issue_Consume(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	svc.FixedCode = "123456"
	svc.IsProd = true

	if err := svc.Issue(ctx, appID, "test@example.com", mail.PurposeRegister); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := svc.Consume(ctx, appID, "test@example.com", "123456", mail.PurposeRegister); err != nil {
		t.Fatalf("Consume: %v", err)
	}
}

func TestService_Consume_WrongCode(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	svc.FixedCode = "123456"
	svc.IsProd = true

	svc.Issue(ctx, appID, "test@example.com", mail.PurposeRegister)

	err := svc.Consume(ctx, appID, "test@example.com", "000000", mail.PurposeRegister)
	if err == nil {
		t.Error("Consume accepted wrong code")
	}
}

func TestService_Consume_ExpiredCode(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	svc.FixedCode = "123456"
	svc.IsProd = true
	svc.TTL = -1 * time.Second // Expired

	svc.Issue(ctx, appID, "test@example.com", mail.PurposeRegister)

	err := svc.Consume(ctx, appID, "test@example.com", "123456", mail.PurposeRegister)
	if err == nil {
		t.Error("Consume accepted expired code")
	}
}
