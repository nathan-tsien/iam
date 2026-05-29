package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	pkgauth "github.com/nathan-tsien/iam/internal/auth"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/repo/app"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
)

var adminTestDB *gorm.DB

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://localhost:5432/iam_test?sslmode=disable"
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("adminrole_test: " + err.Error())
	}
	adminTestDB = db
	os.Exit(m.Run())
}

func setupAdminTest(t *testing.T) (*userrepo.Repo, uuid.UUID) {
	t.Helper()
	adminTestDB.Exec("TRUNCATE TABLE iam.users CASCADE")
	adminTestDB.Exec("TRUNCATE TABLE iam.apps CASCADE")
	appID := uuid.New()
	adminTestDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID, "test-"+appID.String()[:8], "Test App", "test-"+appID.String()[:8], "hash")
	return userrepo.NewRepo(adminTestDB), appID
}

func strPtr(s string) *string { return &s }

func TestAdminRole_ValidAdmin(t *testing.T) {
	userRepo, appID := setupAdminTest(t)

	u := &model.User{AppID: appID, Email: "admin@test.com", PasswordHash: "hash", Role: model.RoleAdmin, DisplayName: strPtr("Admin")}
	userRepo.Create(context.Background(), u)

	signer := pkgauth.NewSigner("test-secret-key-must-be-32-bytes-long!", 15*time.Minute)
	token, _ := signer.Sign(u.ID, "admin", "test")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("app", &app.Model{ID: appID}) })
	r.Use(func(c *gin.Context) {
		claims, _ := signer.Verify(token)
		c.Set("auth.claims", claims)
		c.Next()
	})
	r.Use(middleware.AdminRole(userRepo))
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminRole_NonAdmin(t *testing.T) {
	userRepo, appID := setupAdminTest(t)

	u := &model.User{AppID: appID, Email: "user@test.com", PasswordHash: "hash", Role: model.RoleUser, DisplayName: strPtr("User")}
	userRepo.Create(context.Background(), u)

	signer := pkgauth.NewSigner("test-secret-key-must-be-32-bytes-long!", 15*time.Minute)
	token, _ := signer.Sign(u.ID, "user", "test")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("app", &app.Model{ID: appID}) })
	r.Use(func(c *gin.Context) {
		claims, _ := signer.Verify(token)
		c.Set("auth.claims", claims)
		c.Next()
	})
	r.Use(middleware.AdminRole(userRepo))
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestAdminRole_DisabledUser(t *testing.T) {
	userRepo, appID := setupAdminTest(t)

	now := time.Now()
	u := &model.User{AppID: appID, Email: "disabled@test.com", PasswordHash: "hash", Role: model.RoleAdmin, DisplayName: strPtr("Disabled"), DisabledAt: &now}
	userRepo.Create(context.Background(), u)

	signer := pkgauth.NewSigner("test-secret-key-must-be-32-bytes-long!", 15*time.Minute)
	token, _ := signer.Sign(u.ID, "admin", "test")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("app", &app.Model{ID: appID}) })
	r.Use(func(c *gin.Context) {
		claims, _ := signer.Verify(token)
		c.Set("auth.claims", claims)
		c.Next()
	})
	r.Use(middleware.AdminRole(userRepo))
	r.GET("/test", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}
