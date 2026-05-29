# Wave 4: Self-service and Per-app Admin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `/me` self-service profile, per-app admin user management with audit logging, and admin role middleware.

**Architecture:** New service layer (`userprofile`, `useradmin`) on top of existing user repo, with new `auditlog` repo. Admin middleware does JWT + DB verification. All admin actions write audit logs. Rate limiting on admin endpoints.

**Tech Stack:** Go, Gin, GORM, PostgreSQL, existing `internal/middleware`, `internal/errs`, `internal/ratelimit` patterns.

**Design spec:** `docs/superpowers/specs/2026-05-29-wave4-self-service-admin-design.md`

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `internal/repo/auditlog/repo.go` | Create | Audit log repo (model + Record) |
| `internal/repo/auditlog/repo_test.go` | Create | Audit log repo tests |
| `internal/repo/user/user.go` | Modify | Add UpdateProfile, CountActiveAdmins, List methods |
| `internal/repo/user/user_test.go` | Modify | Tests for new repo methods |
| `internal/middleware/adminrole.go` | Create | Admin role middleware (JWT + DB check) |
| `internal/middleware/adminrole_test.go` | Create | Admin role middleware tests |
| `internal/service/userprofile/service.go` | Create | Userprofile service |
| `internal/service/userprofile/service_test.go` | Create | Userprofile service tests |
| `internal/service/useradmin/service.go` | Create | Useradmin service |
| `internal/service/useradmin/service_test.go` | Create | Useradmin service tests |
| `internal/httpapi/me.go` | Create | /me route handlers |
| `internal/httpapi/users.go` | Create | /users route handlers |
| `cmd/api/main.go` | Modify | Wire new services and routes |

---

### Task 1: auditlog repo

**Files:**
- Create: `internal/repo/auditlog/repo.go`
- Create: `internal/repo/auditlog/repo_test.go`

- [ ] **Step 1: Create auditlog repo**

Create `internal/repo/auditlog/repo.go`:

```go
package auditlog

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Entry mirrors iam.audit_logs.
type Entry struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	AppID     uuid.UUID  `gorm:"type:uuid;not null"`
	ActorID   *uuid.UUID `gorm:"type:uuid"`
	TargetID  *uuid.UUID `gorm:"type:uuid"`
	Action    string     `gorm:"not null"`
	Metadata  JSONB      `gorm:"type:jsonb;not null;default:'{}'::jsonb"`
	CreatedAt time.Time  `gorm:"autoCreateTime"`
}

func (Entry) TableName() string { return "audit_logs" }

// JSONB is a map that GORM serializes to JSONB.
type JSONB map[string]any

type Repo struct {
	DB *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo { return &Repo{DB: db} }

// Record inserts an audit log entry.
func (r *Repo) Record(ctx context.Context, entry *Entry) error {
	return r.DB.WithContext(ctx).Create(entry).Error
}
```

- [ ] **Step 2: Create auditlog repo test**

Create `internal/repo/auditlog/repo_test.go`:

```go
package auditlog_test

import (
	"context"
	"os"
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
		dsn = "postgres://localhost:5432/iam_test?sslmode=disable"
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
	appID := uuid.New()
	testDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID, "test-"+appID.String()[:8], "Test App", "test-"+appID.String()[:8], "hash")
	return auditlog.NewRepo(testDB), appID
}

func TestRepo_Record(t *testing.T) {
	repo, appID := setupTest(t)
	ctx := context.Background()

	actorID := uuid.New()
	targetID := uuid.New()
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
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/repo/auditlog/... -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/repo/auditlog/
git commit -m "feat(repo/auditlog): add audit log repository"
```

---

### Task 2: user repo additions

**Files:**
- Modify: `internal/repo/user/user.go`
- Modify: `internal/repo/user/user_test.go`

- [ ] **Step 1: Add new methods to user repo**

Add to the end of `internal/repo/user/user.go`:

```go
// UpdateProfile patches display_name and/or avatar_url for the given user.
// Nil fields are skipped.
func (r *Repo) UpdateProfile(ctx context.Context, appID, id uuid.UUID, displayName, avatarURL *string) error {
	updates := map[string]any{
		"updated_at": gorm.Expr("NOW()"),
	}
	if displayName != nil {
		updates["display_name"] = *displayName
	}
	if avatarURL != nil {
		updates["avatar_url"] = *avatarURL
	}
	res := r.DB.WithContext(ctx).Model(&model.User{}).
		Where("app_id = ? AND id = ?", appID, id).
		Updates(updates)
	if res.Error != nil {
		if displayName != nil && isUniqueViolation(res.Error) {
			return ErrDisplayNameTaken
		}
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// CountActiveAdmins returns the number of non-disabled admin users in the app.
func (r *Repo) CountActiveAdmins(ctx context.Context, appID uuid.UUID) (int64, error) {
	var count int64
	err := r.DB.WithContext(ctx).
		Model(&model.User{}).
		Where("app_id = ? AND role = 'admin' AND disabled_at IS NULL", appID).
		Count(&count).Error
	return count, err
}

// List returns paginated users with optional search query.
// When query is non-empty, matches against email_lower and display_name (ILIKE).
// Cursor is the ID of the last item from the previous page; empty for the first page.
func (r *Repo) List(ctx context.Context, filter ListFilter) (*ListPage, error) {
	if filter.Limit <= 0 || filter.Limit > 100 {
		filter.Limit = 20
	}

	q := r.DB.WithContext(ctx).Model(&model.User{}).Where("app_id = ?", filter.AppID)

	if filter.Q != "" {
		like := "%" + filter.Q + "%"
		q = q.Where("(email_lower ILIKE ? OR display_name ILIKE ?)", like, like)
	}
	if filter.Role != nil {
		q = q.Where("role = ?", string(*filter.Role))
	}
	if filter.Status != nil {
		switch *filter.Status {
		case StatusActive:
			q = q.Where("disabled_at IS NULL")
		case StatusDisabled:
			q = q.Where("disabled_at IS NOT NULL")
		}
	}

	// Count total before pagination.
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, err
	}

	// Cursor pagination: fetch items after the cursor.
	if filter.Cursor != "" {
		cursorID, err := uuid.Parse(filter.Cursor)
		if err != nil {
			return nil, fmt.Errorf("invalid cursor: %w", err)
		}
		q = q.Where("id > ?", cursorID)
	}

	q = q.Order("created_at ASC, id ASC").Limit(filter.Limit + 1)

	var users []model.User
	if err := q.Find(&users).Error; err != nil {
		return nil, err
	}

	page := &ListPage{
		Items: users,
		Total: total,
	}

	if len(users) > filter.Limit {
		page.Items = users[:filter.Limit]
		page.NextCursor = users[filter.Limit].ID.String()
	}

	return page, nil
}
```

Also add `"fmt"` to the import block at the top of the file if not already present.

- [ ] **Step 2: Add tests for new repo methods**

Add to the end of `internal/repo/user/user_test.go`:

```go
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

	// Create 2 admins, 1 disabled admin, 1 regular user.
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
```

Also add `"fmt"` and `"time"` to the import block of the test file if not already present.

- [ ] **Step 3: Run tests**

Run: `go test ./internal/repo/user/... -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/repo/user/
git commit -m "feat(repo/user): add UpdateProfile, CountActiveAdmins, List methods"
```

---

### Task 3: AdminRole middleware

**Files:**
- Create: `internal/middleware/adminrole.go`
- Create: `internal/middleware/adminrole_test.go`

- [ ] **Step 1: Create AdminRole middleware**

Create `internal/middleware/adminrole.go`:

```go
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/errs"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
)

const adminUserKey = "admin.user"

// AdminRole verifies the authenticated user still has admin role in the DB.
// Must be placed after Auth and AppSlugMiddleware.
func AdminRole(userRepo *userrepo.Repo) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := GetAuthClaims(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing auth claims"))
			c.Abort()
			return
		}

		app, ok := GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			c.Abort()
			return
		}

		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			errs.Render(c, errs.New(http.StatusUnauthorized, "INVALID_TOKEN", "Invalid subject claim"))
			c.Abort()
			return
		}

		u, err := userRepo.FindByID(c.Request.Context(), app.ID, userID)
		if err != nil {
			errs.Render(c, errs.New(http.StatusUnauthorized, "USER_NOT_FOUND", "User not found"))
			c.Abort()
			return
		}

		if u.Disabled() {
			errs.Render(c, errs.New(http.StatusForbidden, "ACCOUNT_DISABLED", "Account is disabled"))
			c.Abort()
			return
		}

		if u.Role != "admin" {
			errs.Render(c, errs.New(http.StatusForbidden, "FORBIDDEN", "Admin access required"))
			c.Abort()
			return
		}

		c.Set(adminUserKey, u)
		c.Next()
	}
}

// GetAdminUser retrieves the model.User verified by AdminRole middleware.
func GetAdminUser(c *gin.Context) (*model.User, bool) {
	v, ok := c.Get(adminUserKey)
	if !ok {
		return nil, false
	}
	u, ok := v.(*model.User)
	return u, ok
}
```

Note: add `"github.com/nathan-tsien/iam/internal/model"` to imports.

- [ ] **Step 2: Create AdminRole middleware test**

Create `internal/middleware/adminrole_test.go`:

```go
package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"context"
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

func init() {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://localhost:5432/iam_test?sslmode=disable"
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("adminrole_test: " + err.Error())
	}
	adminTestDB = db
}

func setupAdminTest(t *testing.T) (*userrepo.Repo, *apprepo.Repo, uuid.UUID) {
	t.Helper()
	adminTestDB.Exec("TRUNCATE TABLE iam.users CASCADE")
	adminTestDB.Exec("TRUNCATE TABLE iam.apps CASCADE")
	appID := uuid.New()
	adminTestDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID, "test-"+appID.String()[:8], "Test App", "test-"+appID.String()[:8], "hash")
	return userrepo.NewRepo(adminTestDB), apprepo.NewRepo(adminTestDB), appID
}

func makeAdminHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	}
}

func strPtr(s string) *string { return &s }

func TestAdminRole_ValidAdmin(t *testing.T) {
	userRepo, _, appID := setupAdminTest(t)

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
	r.GET("/test", makeAdminHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminRole_NonAdmin(t *testing.T) {
	userRepo, _, appID := setupAdminTest(t)

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
	r.GET("/test", makeAdminHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestAdminRole_DisabledUser(t *testing.T) {
	userRepo, _, appID := setupAdminTest(t)

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
	r.GET("/test", makeAdminHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}
```

Note: add missing imports (`os`, `context`, `time`, `app` model).

- [ ] **Step 3: Run tests**

Run: `go test ./internal/middleware/... -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/middleware/adminrole.go internal/middleware/adminrole_test.go
git commit -m "feat(middleware): add AdminRole middleware with DB verification"
```

---

### Task 4: userprofile service

**Files:**
- Create: `internal/service/userprofile/service.go`
- Create: `internal/service/userprofile/service_test.go`

- [ ] **Step 1: Create userprofile service**

Create `internal/service/userprofile/service.go`:

```go
package userprofile

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/model"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
)

type Deps struct {
	UserRepo *userrepo.Repo
}

type Service struct {
	Deps
}

func NewService(d Deps) *Service { return &Service{Deps: d} }

// GetProfile returns the user's profile by ID within an app.
func (s *Service) GetProfile(ctx context.Context, appID, userID uuid.UUID) (*model.User, error) {
	u, err := s.UserRepo.FindByID(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return nil, userrepo.ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// UpdateProfile patches display_name and/or avatar_url.
// Nil fields are left unchanged.
func (s *Service) UpdateProfile(ctx context.Context, appID, userID uuid.UUID, displayName, avatarURL *string) (*model.User, error) {
	if err := s.UserRepo.UpdateProfile(ctx, appID, userID, displayName, avatarURL); err != nil {
		return nil, err
	}
	return s.UserRepo.FindByID(ctx, appID, userID)
}
```

- [ ] **Step 2: Create userprofile service test**

Create `internal/service/userprofile/service_test.go`:

```go
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

func strPtr(s string) *string { return &s }

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
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/service/userprofile/... -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/service/userprofile/
git commit -m "feat(service/userprofile): add userprofile service"
```

---

### Task 5: useradmin service

**Files:**
- Create: `internal/service/useradmin/service.go`
- Create: `internal/service/useradmin/service_test.go`

- [ ] **Step 1: Create useradmin service**

Create `internal/service/useradmin/service.go`:

```go
package useradmin

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/provider/mail"
	"github.com/nathan-tsien/iam/internal/repo/auditlog"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/otp"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrLastAdmin    = errors.New("cannot disable the last admin")
)

type Deps struct {
	UserRepo  *userrepo.Repo
	AuditRepo *auditlog.Repo
	OTP       *otp.Service
}

type Service struct {
	Deps
}

func NewService(d Deps) *Service { return &Service{Deps: d} }

// ListUsers returns paginated users with optional search keyword.
func (s *Service) ListUsers(ctx context.Context, appID uuid.UUID, query string, cursor string, limit int) (*userrepo.ListPage, error) {
	return s.UserRepo.List(ctx, userrepo.ListFilter{
		AppID:  appID,
		Q:      query,
		Cursor: cursor,
		Limit:  limit,
	})
}

// GetUser returns a single user by ID within the app.
func (s *Service) GetUser(ctx context.Context, appID, userID uuid.UUID) (*model.User, error) {
	u, err := s.UserRepo.FindByID(ctx, appID, userID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return u, nil
}

// DisableUser sets disabled_at. Rejects if target is the last active admin.
func (s *Service) DisableUser(ctx context.Context, appID, actorID, targetID uuid.UUID) error {
	target, err := s.UserRepo.FindByID(ctx, appID, targetID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	// Last admin protection.
	if target.Role == model.RoleAdmin && target.DisabledAt == nil {
		count, err := s.UserRepo.CountActiveAdmins(ctx, appID)
		if err != nil {
			return err
		}
		if count <= 1 {
			return ErrLastAdmin
		}
	}

	now := time.Now()
	changed, err := userrepo.SetDisabledAtTx(s.UserRepo.DB.WithContext(ctx), appID, targetID, &now)
	if err != nil {
		return err
	}

	if changed {
		s.writeAudit(ctx, appID, actorID, targetID, "user.disabled", target.Email)
	}

	return nil
}

// EnableUser clears disabled_at. Idempotent.
func (s *Service) EnableUser(ctx context.Context, appID, actorID, targetID uuid.UUID) error {
	target, err := s.UserRepo.FindByID(ctx, appID, targetID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	changed, err := userrepo.SetDisabledAtTx(s.UserRepo.DB.WithContext(ctx), appID, targetID, nil)
	if err != nil {
		return err
	}

	if changed {
		s.writeAudit(ctx, appID, actorID, targetID, "user.enabled", target.Email)
	}

	return nil
}

// TriggerPasswordReset sends a password reset OTP to the target user.
func (s *Service) TriggerPasswordReset(ctx context.Context, appID, actorID, targetID uuid.UUID) error {
	target, err := s.UserRepo.FindByID(ctx, appID, targetID)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	if err := s.OTP.Issue(ctx, appID, target.Email, mail.PurposePasswordReset); err != nil {
		return err
	}

	s.writeAudit(ctx, appID, actorID, targetID, "user.password_reset_triggered", target.Email)

	return nil
}

func (s *Service) writeAudit(ctx context.Context, appID, actorID, targetID uuid.UUID, action, targetEmail string) {
	if s.AuditRepo == nil {
		return
	}
	entry := &auditlog.Entry{
		AppID:    appID,
		ActorID:  &actorID,
		TargetID: &targetID,
		Action:   action,
		Metadata: auditlog.JSONB{"target_email": targetEmail},
	}
	if err := s.AuditRepo.Record(ctx, entry); err != nil {
		slog.Error("write audit log", "action", action, "error", err)
	}
}
```

- [ ] **Step 2: Create useradmin service test**

Create `internal/service/useradmin/service_test.go`:

```go
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

func TestService_DisableUser_HappyPath(t *testing.T) {
	svc, appID := setupTest(t)
	ctx := context.Background()

	actor := createUser(t, appID, "actor@example.com", model.RoleAdmin)
	target := createUser(t, appID, "target@example.com", model.RoleUser)
	_ = actor

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

	for i := 0; i < 3; i++ {
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

func strPtr(s string) *string { return &s }
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/service/useradmin/... -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/service/useradmin/
git commit -m "feat(service/useradmin): add useradmin service with last-admin protection"
```

---

### Task 6: /me HTTP handlers

**Files:**
- Create: `internal/httpapi/me.go`

- [ ] **Step 1: Create /me handlers**

Create `internal/httpapi/me.go`:

```go
package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/userprofile"
)

// RegisterMe mounts /me endpoints on the router.
// Caller must apply Auth middleware to the group.
func RegisterMe(r *gin.RouterGroup, profileSvc *userprofile.Service) {
	r.GET("/me", handleGetMe(profileSvc))
	r.PATCH("/me", handleUpdateMe(profileSvc))
}

func handleGetMe(profileSvc *userprofile.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}
		claims, ok := middleware.GetAuthClaims(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing auth claims"))
			return
		}

		profile, err := profileSvc.GetProfile(c.Request.Context(), app.ID, claims.UserID())
		if err != nil {
			if err == user.ErrNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, userToJSON(profile))
	}
}

func handleUpdateMe(profileSvc *userprofile.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}
		claims, ok := middleware.GetAuthClaims(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing auth claims"))
			return
		}

		var req struct {
			DisplayName *string `json:"display_name"`
			AvatarURL   *string `json:"avatar_url"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if req.DisplayName == nil && req.AvatarURL == nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", "At least one of display_name or avatar_url is required"))
			return
		}

		profile, err := profileSvc.UpdateProfile(c.Request.Context(), app.ID, claims.UserID(), req.DisplayName, req.AvatarURL)
		if err != nil {
			if err == user.ErrDisplayNameTaken {
				errs.Render(c, errs.New(http.StatusConflict, "DISPLAY_NAME_TAKEN", "Display name already taken"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, userToJSON(profile))
	}
}

func userToJSON(u *model.User) gin.H {
	h := gin.H{
		"id":         u.ID,
		"app_id":     u.AppID,
		"email":      u.Email,
		"role":       u.Role,
		"created_at": u.CreatedAt,
		"updated_at": u.UpdatedAt,
	}
	if u.DisplayName != nil {
		h["display_name"] = *u.DisplayName
	}
	if u.AvatarURL != nil {
		h["avatar_url"] = *u.AvatarURL
	}
	if u.EmailVerifiedAt != nil {
		h["email_verified_at"] = *u.EmailVerifiedAt
	}
	if u.DisabledAt != nil {
		h["disabled_at"] = *u.DisabledAt
	}
	return h
}
```

Note: The `Claims` struct has `Subject` as a string (user ID). Add a helper method to `internal/auth/jwt.go`:

```go
// UserID parses the Subject claim as a UUID.
func (c *Claims) UserID() uuid.UUID {
	id, _ := uuid.Parse(c.Subject)
	return id
}
```

- [ ] **Step 2: Run build**

Run: `make build`
Expected: Compiles successfully

- [ ] **Step 3: Commit**

```bash
git add internal/httpapi/me.go internal/auth/jwt.go
git commit -m "feat(httpapi): add /me self-service profile endpoints"
```

---

### Task 7: /users HTTP handlers

**Files:**
- Create: `internal/httpapi/users.go`

- [ ] **Step 1: Create /users handlers**

Create `internal/httpapi/users.go`:

```go
package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/ratelimit"
	"github.com/nathan-tsien/iam/internal/service/useradmin"
)

// RegisterUsers mounts /users endpoints on the router.
// Caller must apply Auth + AdminRole middleware to the group.
func RegisterUsers(r *gin.RouterGroup, adminSvc *useradmin.Service, store ratelimit.Store) {
	if store != nil {
		r.GET("/users",
			middleware.RateLimit(store, 100, time.Minute, func(c *gin.Context) string { return rateLimitKey(c, "admin:users") }),
			handleListUsers(adminSvc))
	} else {
		r.GET("/users", handleListUsers(adminSvc))
	}
	r.GET("/users/:id", handleGetUser(adminSvc))
	r.POST("/users/:id/disable", handleDisableUser(adminSvc))
	r.POST("/users/:id/enable", handleEnableUser(adminSvc))
	r.POST("/users/:id/trigger-password-reset", handleTriggerPasswordReset(adminSvc))
}

func handleListUsers(adminSvc *useradmin.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		query := c.Query("q")
		cursor := c.Query("cursor")
		limit := 20
		if raw := c.Query("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 100 {
				limit = parsed
			}
		}

		page, err := adminSvc.ListUsers(c.Request.Context(), app.ID, query, cursor, limit)
		if err != nil {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		items := make([]gin.H, len(page.Items))
		for i, u := range page.Items {
			items[i] = userToJSON(&u)
		}

		c.JSON(http.StatusOK, gin.H{
			"items":       items,
			"next_cursor": page.NextCursor,
			"total":       page.Total,
		})
	}
}

func handleGetUser(adminSvc *useradmin.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		targetID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_ID", "Invalid user ID"))
			return
		}

		u, err := adminSvc.GetUser(c.Request.Context(), app.ID, targetID)
		if err != nil {
			if err == useradmin.ErrUserNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, userToJSON(u))
	}
}

func handleDisableUser(adminSvc *useradmin.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}
		claims, ok := middleware.GetAuthClaims(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing auth claims"))
			return
		}

		targetID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_ID", "Invalid user ID"))
			return
		}

		if err := adminSvc.DisableUser(c.Request.Context(), app.ID, claims.UserID(), targetID); err != nil {
			switch err {
			case useradmin.ErrUserNotFound:
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
			case useradmin.ErrLastAdmin:
				errs.Render(c, errs.New(http.StatusConflict, "LAST_ADMIN", "Cannot disable the last admin"))
			default:
				errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{"disabled": true})
	}
}

func handleEnableUser(adminSvc *useradmin.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}
		claims, ok := middleware.GetAuthClaims(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing auth claims"))
			return
		}

		targetID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_ID", "Invalid user ID"))
			return
		}

		if err := adminSvc.EnableUser(c.Request.Context(), app.ID, claims.UserID(), targetID); err != nil {
			if err == useradmin.ErrUserNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, gin.H{"enabled": true})
	}
}

func handleTriggerPasswordReset(adminSvc *useradmin.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}
		claims, ok := middleware.GetAuthClaims(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing auth claims"))
			return
		}

		targetID, err := uuid.Parse(c.Param("id"))
		if err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_ID", "Invalid user ID"))
			return
		}

		if err := adminSvc.TriggerPasswordReset(c.Request.Context(), app.ID, claims.UserID(), targetID); err != nil {
			if err == useradmin.ErrUserNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "USER_NOT_FOUND", "User not found"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
	}
}
```

- [ ] **Step 2: Run build**

Run: `make build`
Expected: Compiles successfully

- [ ] **Step 3: Commit**

```bash
git add internal/httpapi/users.go
git commit -m "feat(httpapi): add /users admin endpoints"
```

---

### Task 8: main.go wiring

**Files:**
- Modify: `cmd/api/main.go`

- [ ] **Step 1: Wire new services and routes in main.go**

Add imports to `cmd/api/main.go`:

```go
auditlogrepo "github.com/nathan-tsien/iam/internal/repo/auditlog"
userprofilesvc "github.com/nathan-tsien/iam/internal/service/userprofile"
useradminsvc "github.com/nathan-tsien/iam/internal/service/useradmin"
```

After the existing `httpapi.RegisterAuth(v1, authSvc, rlStore)` line, add:

```go
// --- Wave 4: self-service + admin ---
auditRepo := auditlogrepo.NewRepo(gormDB)
profileSvc := userprofilesvc.NewService(userprofilesvc.Deps{UserRepo: userRepo})
adminSvc := useradminsvc.NewService(useradminsvc.Deps{
	UserRepo:  userRepo,
	AuditRepo: auditRepo,
	OTP:       otpSvc,
})

// /me routes (auth required)
me := v1.Group("")
me.Use(middleware.Auth(signer))
httpapi.RegisterMe(me, profileSvc)

// /users routes (auth + admin required)
admin := v1.Group("")
admin.Use(middleware.Auth(signer))
admin.Use(middleware.AdminRole(userRepo))
httpapi.RegisterUsers(admin, adminSvc, rlStore)
```

- [ ] **Step 2: Run build**

Run: `make build`
Expected: Compiles successfully

- [ ] **Step 3: Commit**

```bash
git add cmd/api/main.go
git commit -m "feat(api): wire userprofile, useradmin, auditlog services"
```

---

### Task 9: Tracker update

**Files:**
- Modify: `docs/migration/tracker.md`
- Modify: `docs/migration/implementation-path.md` (if needed)

- [ ] **Step 1: Update tracker**

Update the tracker to reflect Wave 4 progress. The implementation-path.md marks Wave 4 as steps 4.1, 4.2, 4.3. Update the current position.

- [ ] **Step 2: Run lint and test**

Run: `make lint && make test`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add docs/migration/tracker.md
git commit -m "docs(tracker): mark Wave 4 complete"
```
