# Wave 2: Auth Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift auth modules from source repo, implement hybrid routing (URL path for unauthenticated, JWT aud for authenticated), and scope all queries by app_id.

**Architecture:** Full lift from `family-office-platform/backend/internal/` with import path changes, business field removal, and app_id scoping. Three PRs: (1) auth + repo layer, (2) service + middleware layer, (3) HTTP wiring.

**Tech Stack:** Go 1.25+, Gin, GORM, golang-jwt/jwt/v5, bcrypt, goose migrations

---

## PR-1: Auth + Repo Layer

### Task 1: Create errs package

**Files:**
- Create: `internal/errs/errs.go`

The errs package provides unified error handling for HTTP responses.

- [ ] **Step 1: Create errs package**

```go
package errs

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

const RequestIDKey = "request_id"

type AppError struct {
	Code       string
	Message    string
	HTTPStatus int
	Details    map[string]any
	Cause      error
}

func (e *AppError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error { return e.Cause }

func New(status int, code, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: status,
	}
}

func (e *AppError) WithDetails(details map[string]any) *AppError {
	clone := *e
	clone.Details = details
	return &clone
}

func (e *AppError) WithCause(cause error) *AppError {
	clone := *e
	clone.Cause = cause
	return &clone
}

func Render(c *gin.Context, err error) {
	var app *AppError
	if !errors.As(err, &app) {
		app = &AppError{
			Code:       "INTERNAL",
			Message:    "Internal server error",
			HTTPStatus: http.StatusInternalServerError,
			Cause:      err,
		}
	}

	requestID, _ := c.Get(RequestIDKey)
	rid, _ := requestID.(string)

	payload := gin.H{
		"code":       app.Code,
		"message":    app.Message,
		"request_id": rid,
	}
	if app.Details != nil {
		payload["details"] = app.Details
	}

	c.JSON(app.HTTPStatus, payload)
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./internal/errs/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/errs/errs.go
git commit -m "feat(errs): add unified error handling package"
```

---

### Task 2: Create mail package (interface + types only)

**Files:**
- Create: `internal/provider/mail/mail.go`
- Create: `internal/provider/mail/locale.go`

Lift the mail interface and locale types. No SMTP implementation yet (Wave 3).

- [ ] **Step 1: Create mail.go**

```go
package mail

import "context"

type Purpose string

const (
	PurposeRegister      Purpose = "register"
	PurposePasswordReset Purpose = "password_reset"
)

type Mailer interface {
	SendOTP(ctx context.Context, email, code string, purpose Purpose, locale Locale) error
}
```

- [ ] **Step 2: Create locale.go**

```go
package mail

import (
	"context"
	"strings"
)

type Locale string

const (
	LocaleZhCN Locale = "zh-CN"
	LocaleZhTW Locale = "zh-TW"
	LocaleEnUS Locale = "en-US"
)

func Normalize(s string) Locale {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return LocaleZhCN
	}
	if strings.HasPrefix(lower, "zh") {
		for _, sub := range strings.Split(lower, "-")[1:] {
			switch sub {
			case "tw", "hk", "mo", "hant":
				return LocaleZhTW
			}
		}
		return LocaleZhCN
	}
	if strings.HasPrefix(lower, "en") {
		return LocaleEnUS
	}
	return LocaleZhCN
}

type localeKey struct{}

func WithLocale(ctx context.Context, loc Locale) context.Context {
	return context.WithValue(ctx, localeKey{}, loc)
}

func LocaleFrom(ctx context.Context) Locale {
	if ctx == nil {
		return LocaleZhCN
	}
	if v, ok := ctx.Value(localeKey{}).(Locale); ok {
		return v
	}
	return LocaleZhCN
}
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./internal/provider/mail/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/provider/mail/mail.go internal/provider/mail/locale.go
git commit -m "feat(mail): add mailer interface and locale types"
```

---

### Task 3: Lift auth package (JWT + password + policy)

**Files:**
- Create: `internal/auth/jwt.go`
- Create: `internal/auth/jwt_test.go`
- Create: `internal/auth/password.go`
- Create: `internal/auth/password_test.go`
- Create: `internal/auth/passwordpolicy/policy.go`

Lift from source with import path change. Add `Audience` to Claims for hybrid routing.

- [ ] **Step 1: Create jwt.go**

```go
package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims is the JWT payload carried by access tokens.
type Claims struct {
	Role     string `json:"role"`
	Audience string `json:"aud"`
	jwt.RegisteredClaims
}

// Signer signs and verifies access tokens using HS256.
type Signer struct {
	secret []byte
	ttl    time.Duration
}

const minSecretBytes = 32

func NewSigner(secret string, ttl time.Duration) *Signer {
	if len(secret) < minSecretBytes {
		panic(fmt.Sprintf("auth.NewSigner: secret must be at least %d bytes, got %d", minSecretBytes, len(secret)))
	}
	return &Signer{secret: []byte(secret), ttl: ttl}
}

// Sign issues a new token for the given user with the role and audience embedded.
func (s *Signer) Sign(userID uuid.UUID, role, audience string) (string, error) {
	now := time.Now()
	claims := Claims{
		Role:     role,
		Audience: audience,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(s.secret)
}

// Verify parses and validates a token string, returning the claims on success.
func (s *Signer) Verify(tokenStr string) (*Claims, error) {
	t, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := t.Claims.(*Claims)
	if !ok || !t.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
```

- [ ] **Step 2: Create jwt_test.go**

```go
package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	return NewSigner("this-secret-is-exactly-32-bytes!", 5*time.Minute)
}

func TestSigner_SignVerify_RoundTrip(t *testing.T) {
	s := newTestSigner(t)
	uid := uuid.New()

	token, err := s.Sign(uid, "user", "demo")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}

	claims, err := s.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != uid.String() {
		t.Errorf("Subject = %q, want %q", claims.Subject, uid.String())
	}
	if claims.Role != "user" {
		t.Errorf("Role = %q, want user", claims.Role)
	}
	if claims.Audience != "demo" {
		t.Errorf("Audience = %q, want demo", claims.Audience)
	}
	if claims.ID == "" {
		t.Error("JTI empty")
	}
}

func TestSigner_Verify_RejectsTamperedToken(t *testing.T) {
	s := newTestSigner(t)
	token, _ := s.Sign(uuid.New(), "user", "demo")
	tampered := token[:len(token)-1] + "X"
	if _, err := s.Verify(tampered); err == nil {
		t.Error("Verify accepted tampered token")
	}
}

func TestSigner_Verify_RejectsExpiredToken(t *testing.T) {
	s := NewSigner("this-secret-is-exactly-32-bytes!", -1*time.Second)
	token, _ := s.Sign(uuid.New(), "user", "demo")
	if _, err := s.Verify(token); err == nil {
		t.Error("Verify accepted expired token")
	}
}

func TestSigner_Verify_RejectsMalformed(t *testing.T) {
	s := newTestSigner(t)
	for _, in := range []string{"", "not-a-jwt", "a.b.c"} {
		if _, err := s.Verify(in); err == nil {
			t.Errorf("Verify(%q) accepted", in)
		}
	}
}

func TestNewSigner_PanicsOnShortSecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("NewSigner did not panic on short secret")
		}
	}()
	_ = NewSigner("too-short", time.Minute)
}

func TestSigner_Verify_RejectsWrongSecret(t *testing.T) {
	a := NewSigner("this-secret-is-exactly-32-bytes!", 5*time.Minute)
	b := NewSigner("another-secret-that-is-32-bytes!", 5*time.Minute)
	token, _ := a.Sign(uuid.New(), "user", "demo")
	if _, err := b.Verify(token); err == nil {
		t.Error("Verify accepted token signed with different secret")
	}
}
```

- [ ] **Step 3: Create password.go**

```go
package auth

import "golang.org/x/crypto/bcrypt"

func HashPassword(plaintext string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func VerifyPassword(hash, plaintext string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}
```

- [ ] **Step 4: Create password_test.go**

```go
package auth

import "testing"

func TestHashPassword_RoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("hash is empty")
	}
	if err := VerifyPassword(hash, "correct horse battery staple"); err != nil {
		t.Errorf("VerifyPassword with correct plaintext: %v", err)
	}
}

func TestVerifyPassword_RejectsWrong(t *testing.T) {
	hash, _ := HashPassword("secret")
	if err := VerifyPassword(hash, "wrong"); err == nil {
		t.Error("VerifyPassword accepted wrong password")
	}
}

func TestHashPassword_DifferentHashesForSameInput(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("bcrypt produced identical hashes; salting likely broken")
	}
}
```

- [ ] **Step 5: Create passwordpolicy/policy.go**

```go
package passwordpolicy

import (
	"sort"
	"unicode"
)

const (
	MinLength       = 8
	MaxLength       = 128
	MaxBytes        = 72
	RequiredClasses = 3
)

const (
	RuleMinLength             = "min_length"
	RuleMaxLength             = "max_length"
	RuleMaxBytes              = "max_bytes"
	RuleCharClasses           = "char_classes"
	RuleSurroundingWhitespace = "surrounding_whitespace"
)

func Validate(pw string) []string {
	var fails []string

	runes := []rune(pw)
	if len(runes) < MinLength {
		fails = append(fails, RuleMinLength)
	}
	if len(runes) > MaxLength {
		fails = append(fails, RuleMaxLength)
	}
	if len(pw) > MaxBytes {
		fails = append(fails, RuleMaxBytes)
	}

	var upper, lower, digit, other bool
	for _, r := range runes {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, ok := range []bool{upper, lower, digit, other} {
		if ok {
			classes++
		}
	}
	if classes < RequiredClasses {
		fails = append(fails, RuleCharClasses)
	}

	if len(runes) > 0 {
		if unicode.IsSpace(runes[0]) || unicode.IsSpace(runes[len(runes)-1]) {
			fails = append(fails, RuleSurroundingWhitespace)
		}
	}

	if len(fails) == 0 {
		return nil
	}
	sort.Strings(fails)
	return fails
}
```

- [ ] **Step 6: Verify compilation and tests**

Run: `go test ./internal/auth/... -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/auth/ internal/auth/passwordpolicy/
git commit -m "feat(auth): lift JWT, password, and password policy from source"
```

---

### Task 4: Create user repo with app_id scoping

**Files:**
- Create: `internal/model/user.go`
- Create: `internal/repo/user/user.go`
- Create: `internal/repo/user/user_test.go`

Lift from source, add `AppID` field, remove `Tier` and `AgentMemoryPaused`, scope all queries by `app_id`.

- [ ] **Step 1: Create model/user.go**

```go
package model

import (
	"time"

	"github.com/google/uuid"
)

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// User mirrors iam.users. Business fields (tier, agent_memory_paused) are excluded.
type User struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	AppID          uuid.UUID  `gorm:"type:uuid;not null;index"`
	Email          string     `gorm:"not null"`
	EmailLower     string     `gorm:"column:email_lower;not null"`
	PasswordHash   string     `gorm:"not null"`
	Role           Role       `gorm:"type:text;not null;default:'user'"`
	DisplayName    *string    `gorm:"type:varchar(100)"`
	AvatarURL      *string    `gorm:"type:text"`
	EmailVerifiedAt *time.Time
	DisabledAt     *time.Time
	DeletedAt      *time.Time
	CreatedAt      time.Time  `gorm:"autoCreateTime"`
	UpdatedAt      time.Time  `gorm:"autoUpdateTime"`
}

func (User) TableName() string { return "users" }

func (u *User) EmailVerified() bool { return u.EmailVerifiedAt != nil }
func (u *User) Disabled() bool      { return u.DisabledAt != nil }

func (u *User) ApplicantName() string {
	if u.DisplayName != nil && *u.DisplayName != "" {
		return *u.DisplayName
	}
	return u.Email
}
```

- [ ] **Step 2: Create repo/user/user.go**

```go
package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/model"
)

var (
	ErrNotFound         = errors.New("user not found")
	ErrEmailTaken       = errors.New("email already registered")
	ErrDisplayNameTaken = errors.New("display name already taken")
)

type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

type ListFilter struct {
	AppID  uuid.UUID
	Q      string
	Role   *model.Role
	Status *Status
	Cursor string
	Limit  int
}

type SearchFilter struct {
	AppID uuid.UUID
	Q     string
	Limit int
}

type ListPage struct {
	Items      []model.User
	NextCursor string
	Total      int64
}

type Repo struct {
	DB *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo { return &Repo{DB: db} }

// Create inserts a new user. Email is lower-cased for uniqueness.
func (r *Repo) Create(ctx context.Context, u *model.User) error {
	u.Email = strings.ToLower(u.Email)
	u.EmailLower = u.Email
	err := r.DB.WithContext(ctx).Create(u).Error
	if err != nil && isUniqueViolation(err) {
		constraint := uniqueViolationConstraint(err)
		if constraint == "users_app_email_lower_key" || constraint == "idx_users_display_name_unique" {
			return ErrEmailTaken
		}
		return ErrEmailTaken
	}
	return err
}

// FindByEmail returns the user with the given email within an app, or ErrNotFound.
func (r *Repo) FindByEmail(ctx context.Context, appID uuid.UUID, email string) (*model.User, error) {
	var u model.User
	err := r.DB.WithContext(ctx).
		Where("app_id = ? AND email_lower = ?", appID, strings.ToLower(email)).
		First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &u, err
}

// FindByID returns the user with the given id within an app, or ErrNotFound.
func (r *Repo) FindByID(ctx context.Context, appID, id uuid.UUID) (*model.User, error) {
	var u model.User
	err := r.DB.WithContext(ctx).
		Where("app_id = ? AND id = ?", appID, id).
		First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &u, err
}

// SetEmailVerified marks the user's email as verified.
func (r *Repo) SetEmailVerified(ctx context.Context, appID, id uuid.UUID) error {
	res := r.DB.WithContext(ctx).Model(&model.User{}).
		Where("app_id = ? AND id = ?", appID, id).
		Updates(map[string]any{
			"email_verified_at": gorm.Expr("NOW()"),
			"updated_at":        gorm.Expr("NOW()"),
		})
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return res.Error
}

// UpdatePassword sets a new password_hash for the given user.
func (r *Repo) UpdatePassword(ctx context.Context, appID, id uuid.UUID, hash string) error {
	res := r.DB.WithContext(ctx).Model(&model.User{}).
		Where("app_id = ? AND id = ?", appID, id).
		Updates(map[string]any{
			"password_hash": hash,
			"updated_at":    gorm.Expr("NOW()"),
		})
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return res.Error
}

// DisplayNameExists reports whether a user with the given display_name exists in the app.
func (r *Repo) DisplayNameExists(ctx context.Context, appID uuid.UUID, name string) (bool, error) {
	var count int64
	err := r.DB.WithContext(ctx).
		Model(&model.User{}).
		Where("app_id = ? AND display_name = ?", appID, name).
		Count(&count).Error
	return count > 0, err
}

// DisplayNameExistsExcept reports whether a user other than exceptID owns
// the given display_name in the app.
func (r *Repo) DisplayNameExistsExcept(ctx context.Context, appID uuid.UUID, name string, exceptID uuid.UUID) (bool, error) {
	var count int64
	err := r.DB.WithContext(ctx).
		Model(&model.User{}).
		Where("app_id = ? AND display_name = ? AND id <> ?", appID, name, exceptID).
		Count(&count).Error
	return count > 0, err
}

// UpdateRegistration overwrites password_hash and display_name.
func (r *Repo) UpdateRegistration(ctx context.Context, appID, id uuid.UUID, hash, displayName string) error {
	res := r.DB.WithContext(ctx).Model(&model.User{}).
		Where("app_id = ? AND id = ?", appID, id).
		Updates(map[string]any{
			"password_hash": hash,
			"display_name":  displayName,
			"updated_at":    gorm.Expr("NOW()"),
		})
	if res.Error != nil {
		if isUniqueViolation(res.Error) {
			return ErrDisplayNameTaken
		}
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// SetDisabledAtTx flips users.disabled_at within an outer tx.
func SetDisabledAtTx(tx *gorm.DB, appID, id uuid.UUID, at *time.Time) (changed bool, err error) {
	var where string
	if at != nil {
		where = "app_id = ? AND id = ? AND disabled_at IS NULL"
	} else {
		where = "app_id = ? AND id = ? AND disabled_at IS NOT NULL"
	}
	res := tx.Model(&model.User{}).Where(where, appID, id).Update("disabled_at", at)
	return res.RowsAffected == 1, res.Error
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate key value") || strings.Contains(msg, "SQLSTATE 23505")
}

func uniqueViolationConstraint(err error) string {
	msg := err.Error()
	const marker = `unique constraint "`
	if i := strings.Index(msg, marker); i >= 0 {
		start := i + len(marker)
		if end := strings.Index(msg[start:], `"`); end >= 0 {
			return msg[start : start+end]
		}
	}
	return ""
}
```

- [ ] **Step 3: Create repo/user/user_test.go**

```go
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
	// Truncate users table
	testDB.Exec("TRUNCATE TABLE iam.users CASCADE")
	// Create a test app
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

	// Create second app
	appID2 := uuid.New()
	testDB.Exec("INSERT INTO iam.apps (id, slug, display_name, jwt_audience, hmac_secret_hash) VALUES (?, ?, ?, ?, ?)",
		appID2, "test-"+appID2.String()[:8], "Test App 2", "test-"+appID2.String()[:8], "hash")

	// Same email in different app should not be found
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
```

- [ ] **Step 4: Verify compilation**

Run: `go build ./internal/model/... ./internal/repo/user/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/model/ internal/repo/user/
git commit -m "feat(repo/user): lift user repo with app_id scoping"
```

---

### Task 5: Create refresh token repo with app_id scoping

**Files:**
- Create: `internal/repo/refresh/refresh.go`
- Create: `internal/repo/refresh/refresh_test.go`

Lift from source, add `AppID` field to Token model.

- [ ] **Step 1: Create repo/refresh/refresh.go**

```go
package refresh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

var ErrNotFound = errors.New("refresh token not found, revoked, or expired")

// Token mirrors iam.refresh_tokens.
type Token struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID    uuid.UUID `gorm:"type:uuid;not null"`
	AppID     uuid.UUID `gorm:"type:uuid;not null;index"`
	TokenHash string    `gorm:"not null"`
	IssuedAt  time.Time `gorm:"autoCreateTime"`
	ExpiresAt time.Time `gorm:"not null"`
	RevokedAt *time.Time
}

func (Token) TableName() string { return "refresh_tokens" }

type Repo struct {
	DB *gorm.DB
}

func NewRepo(db *gorm.DB) *Repo { return &Repo{DB: db} }

// Generate issues a new refresh token for userID within an app.
func (r *Repo) Generate(ctx context.Context, appID, userID uuid.UUID, ttl time.Duration) (string, error) {
	plain, err := randomToken()
	if err != nil {
		return "", err
	}
	row := &Token{
		UserID:    userID,
		AppID:     appID,
		TokenHash: hashToken(plain),
		ExpiresAt: time.Now().Add(ttl),
	}
	if err := r.DB.WithContext(ctx).Create(row).Error; err != nil {
		return "", err
	}
	return plain, nil
}

// Lookup finds a valid (not revoked, not expired) token by plaintext value.
func (r *Repo) Lookup(ctx context.Context, plain string) (*Token, error) {
	var row Token
	err := r.DB.WithContext(ctx).
		Where("token_hash = ? AND revoked_at IS NULL AND expires_at > NOW()", hashToken(plain)).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &row, err
}

// Revoke marks the given token revoked.
func (r *Repo) Revoke(ctx context.Context, plain string) error {
	now := time.Now()
	res := r.DB.WithContext(ctx).Model(&Token{}).
		Where("token_hash = ? AND revoked_at IS NULL", hashToken(plain)).
		Update("revoked_at", now)
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return res.Error
}

// Rotate atomically revokes the old token and issues a new one for the same user.
// Replay detection: if the presented token exists but is already revoked,
// revoke every active refresh token for that user.
func (r *Repo) Rotate(ctx context.Context, oldPlain string, ttl time.Duration) (newPlain string, userID uuid.UUID, appID uuid.UUID, err error) {
	var notFound bool
	err = r.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var old Token
		if lookupErr := tx.Where(
			"token_hash = ? AND revoked_at IS NULL AND expires_at > NOW()",
			hashToken(oldPlain),
		).First(&old).Error; lookupErr != nil {
			if errors.Is(lookupErr, gorm.ErrRecordNotFound) {
				notFound = true
				// Replay detection
				var revoked Token
				if err := tx.Where("token_hash = ?", hashToken(oldPlain)).First(&revoked).Error; err == nil && revoked.RevokedAt != nil {
					if _, rErr := RevokeAllForUserTx(tx, revoked.UserID); rErr != nil {
						return fmt.Errorf("revoke on replay: %w", rErr)
					}
				}
				return nil
			}
			return lookupErr
		}
		now := time.Now()
		if err := tx.Model(&Token{}).Where("id = ?", old.ID).Update("revoked_at", now).Error; err != nil {
			return err
		}
		userID = old.UserID
		appID = old.AppID
		nPlain, nErr := randomToken()
		if nErr != nil {
			return nErr
		}
		newPlain = nPlain
		return tx.Create(&Token{
			UserID:    old.UserID,
			AppID:     old.AppID,
			TokenHash: hashToken(nPlain),
			ExpiresAt: now.Add(ttl),
		}).Error
	})
	if err == nil && notFound {
		err = ErrNotFound
	}
	return
}

// RevokeAllForUser invalidates every active refresh token for a user.
func (r *Repo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := RevokeAllForUserTx(r.DB.WithContext(ctx), userID)
	return err
}

// RevokeAllForUserTx marks every active refresh token for userID as revoked.
func RevokeAllForUserTx(tx *gorm.DB, userID uuid.UUID) (int64, error) {
	res := tx.Model(&Token{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", time.Now().UTC())
	return res.RowsAffected, res.Error
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func hashToken(plain string) string {
	h := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(h[:])
}
```

- [ ] **Step 2: Create repo/refresh/refresh_test.go**

```go
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
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./internal/repo/refresh/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/repo/refresh/
git commit -m "feat(repo/refresh): lift refresh token repo with app_id scoping"
```

---

## PR-2: Service + Middleware Layer

### Task 6: Create OTP service with app_id scoping

**Files:**
- Create: `internal/service/otp/otp.go`
- Create: `internal/service/otp/otp_test.go`

Lift from source, add `appID` parameter to Issue/Consume.

- [ ] **Step 1: Create service/otp/otp.go**

```go
package otp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/provider/mail"
)

const (
	CodeLength = 6
	DefaultTTL = 10 * time.Minute
)

var (
	ErrNotFound     = errors.New("no active OTP found")
	ErrCodeMismatch = errors.New("OTP code does not match")
)

// Code mirrors iam.otp_codes.
type Code struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	AppID      uuid.UUID `gorm:"type:uuid;not null;index"`
	Email      string    `gorm:"column:email_lower;not null"`
	CodeHash   string    `gorm:"not null"`
	Purpose    string    `gorm:"type:text;not null"`
	ExpiresAt  time.Time `gorm:"not null"`
	ConsumedAt *time.Time
	CreatedAt  time.Time `gorm:"autoCreateTime"`
}

func (Code) TableName() string { return "otp_codes" }

type Service struct {
	DB        *gorm.DB
	Mailer    mail.Mailer
	TTL       time.Duration
	FixedCode string
	Logger    *slog.Logger
	IsProd    bool
}

func NewService(db *gorm.DB, mailer mail.Mailer, ttl time.Duration) *Service {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Service{DB: db, Mailer: mailer, TTL: ttl}
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// Issue generates a new 6-digit code, stores its SHA-256 hash with expiry,
// and dispatches the plaintext via the Mailer.
func (s *Service) Issue(ctx context.Context, appID uuid.UUID, email string, purpose mail.Purpose) error {
	var code string
	if s.FixedCode != "" {
		code = s.FixedCode
		s.logger().Warn("dev fixed OTP in use",
			"email", email,
			"purpose", string(purpose))
	} else {
		random, err := randomDigits(CodeLength)
		if err != nil {
			return fmt.Errorf("generate code: %w", err)
		}
		code = random
	}
	now := time.Now()
	row := &Code{
		AppID:     appID,
		Email:     email,
		CodeHash:  hashCode(code),
		Purpose:   string(purpose),
		ExpiresAt: now.Add(s.TTL),
	}
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Code{}).
			Where("app_id = ? AND email_lower = ? AND purpose = ? AND consumed_at IS NULL",
				appID, email, string(purpose)).
			Update("consumed_at", now).Error; err != nil {
			return fmt.Errorf("invalidate prior otps: %w", err)
		}
		if err := tx.Create(row).Error; err != nil {
			return fmt.Errorf("persist code: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	locale := mail.LocaleFrom(ctx)
	if !s.IsProd {
		s.logger().InfoContext(ctx, "dev-aid: OTP code issued",
			"email", email,
			"purpose", string(purpose),
			"code", code,
			"locale", string(locale),
		)
	}
	return s.Mailer.SendOTP(ctx, email, code, purpose, locale)
}

// Consume verifies the code for email+purpose and marks it consumed.
func (s *Service) Consume(ctx context.Context, appID uuid.UUID, email, code string, purpose mail.Purpose) error {
	var row Code
	err := s.DB.WithContext(ctx).
		Where("app_id = ? AND email_lower = ? AND purpose = ? AND consumed_at IS NULL AND expires_at > NOW()",
			appID, email, string(purpose)).
		Order("created_at DESC").
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if row.CodeHash != hashCode(code) {
		return ErrCodeMismatch
	}
	now := time.Now()
	return s.DB.WithContext(ctx).Model(&Code{}).
		Where("id = ?", row.ID).
		Update("consumed_at", now).Error
}

func randomDigits(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	digits := make([]byte, n)
	for i := range buf {
		digits[i] = '0' + (buf[i] % 10)
	}
	return string(digits), nil
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}
```

- [ ] **Step 2: Create service/otp/otp_test.go**

```go
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

	// Use fixed code for testing
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
```

- [ ] **Step 3: Verify compilation**

Run: `go build ./internal/service/otp/...`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/service/otp/
git commit -m "feat(service/otp): lift OTP service with app_id scoping"
```

---

### Task 7: Create auth service with app_id scoping

**Files:**
- Create: `internal/service/auth/auth.go`
- Create: `internal/service/auth/auth_test.go`

Lift from source, add `appID` parameter to all methods.

- [ ] **Step 1: Create service/auth/auth.go**

```go
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	pkgauth "github.com/nathan-tsien/iam/internal/auth"
	"github.com/nathan-tsien/iam/internal/auth/passwordpolicy"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/provider/mail"
	"github.com/nathan-tsien/iam/internal/repo/refresh"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/otp"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrInvalidRefresh     = errors.New("invalid refresh token")
	ErrAccountDisabled    = errors.New("account disabled")
	ErrDisplayNameTaken   = errors.New("display name already taken")
)

type ErrWeakPassword struct {
	FailedRules []string
}

func (e *ErrWeakPassword) Error() string {
	return "weak password: " + strings.Join(e.FailedRules, ",")
}

type Deps struct {
	UserRepo    *userrepo.Repo
	RefreshRepo *refresh.Repo
	OTP         *otp.Service
	Signer      *pkgauth.Signer
	RefreshTTL  time.Duration
}

type Service struct {
	Deps
}

func NewService(d Deps) *Service { return &Service{Deps: d} }

type RegisterResponse struct {
	UserID      uuid.UUID
	Email       string
	DisplayName string
}

// Register creates an unverified user and dispatches a register OTP.
func (s *Service) Register(ctx context.Context, appID uuid.UUID, email, plaintextPassword, displayName string) (*RegisterResponse, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return nil, errors.New("display_name is required")
	}
	if fails := passwordpolicy.Validate(plaintextPassword); len(fails) > 0 {
		return nil, &ErrWeakPassword{FailedRules: fails}
	}
	hash, err := pkgauth.HashPassword(plaintextPassword)
	if err != nil {
		return nil, err
	}

	existing, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil && !errors.Is(err, userrepo.ErrNotFound) {
		return nil, fmt.Errorf("lookup email: %w", err)
	}

	if existing != nil {
		if existing.EmailVerified() {
			return nil, userrepo.ErrEmailTaken
		}
		taken, err := s.UserRepo.DisplayNameExistsExcept(ctx, appID, displayName, existing.ID)
		if err != nil {
			return nil, fmt.Errorf("check display_name: %w", err)
		}
		if taken {
			return nil, ErrDisplayNameTaken
		}
		if err := s.UserRepo.UpdateRegistration(ctx, appID, existing.ID, hash, displayName); err != nil {
			if errors.Is(err, userrepo.ErrDisplayNameTaken) {
				return nil, ErrDisplayNameTaken
			}
			return nil, err
		}
		if err := s.OTP.Issue(ctx, appID, email, mail.PurposeRegister); err != nil {
			return nil, err
		}
		return &RegisterResponse{UserID: existing.ID, Email: email, DisplayName: displayName}, nil
	}

	exists, err := s.UserRepo.DisplayNameExists(ctx, appID, displayName)
	if err != nil {
		return nil, fmt.Errorf("check display_name: %w", err)
	}
	if exists {
		return nil, ErrDisplayNameTaken
	}
	u := &model.User{
		AppID:        appID,
		Email:        email,
		PasswordHash: hash,
		DisplayName:  &displayName,
	}
	if err := s.UserRepo.Create(ctx, u); err != nil {
		return nil, err
	}
	if err := s.OTP.Issue(ctx, appID, email, mail.PurposeRegister); err != nil {
		return nil, err
	}
	return &RegisterResponse{UserID: u.ID, Email: u.Email, DisplayName: displayName}, nil
}

type AvailabilityResult struct {
	EmailAvailable       *bool
	DisplayNameAvailable *bool
}

func (s *Service) CheckAvailability(ctx context.Context, appID uuid.UUID, email, displayName string) (*AvailabilityResult, error) {
	res := &AvailabilityResult{}

	if email != "" {
		normalized := strings.ToLower(strings.TrimSpace(email))
		u, err := s.UserRepo.FindByEmail(ctx, appID, normalized)
		switch {
		case err == nil:
			available := !u.EmailVerified()
			res.EmailAvailable = &available
		case errors.Is(err, userrepo.ErrNotFound):
			available := true
			res.EmailAvailable = &available
		default:
			return nil, fmt.Errorf("check email availability: %w", err)
		}
	}

	if displayName != "" {
		exists, err := s.UserRepo.DisplayNameExists(ctx, appID, displayName)
		if err != nil {
			return nil, fmt.Errorf("check display_name availability: %w", err)
		}
		available := !exists
		res.DisplayNameAvailable = &available
	}

	return res, nil
}

// VerifyRegisterOTP consumes a register-purpose code and marks the user verified.
func (s *Service) VerifyRegisterOTP(ctx context.Context, appID uuid.UUID, email, code string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if err := s.OTP.Consume(ctx, appID, email, code, mail.PurposeRegister); err != nil {
		return err
	}
	u, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil {
		return err
	}
	return s.UserRepo.SetEmailVerified(ctx, appID, u.ID)
}

type LoginTokens struct {
	AccessToken  string
	RefreshToken string
	User         *model.User
}

// Login verifies credentials and issues tokens.
func (s *Service) Login(ctx context.Context, appID uuid.UUID, email, plaintextPassword, audience string) (*LoginTokens, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := s.UserRepo.FindByEmail(ctx, appID, email)
	if err != nil {
		if errors.Is(err, userrepo.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if err := pkgauth.VerifyPassword(u.PasswordHash, plaintextPassword); err != nil {
		return nil, ErrInvalidCredentials
	}
	if !u.EmailVerified() {
		return nil, ErrEmailNotVerified
	}
	if u.Disabled() {
		return nil, ErrAccountDisabled
	}
	return s.issueTokens(ctx, appID, u, audience)
}

// Refresh rotates a refresh token and issues a new access token.
func (s *Service) Refresh(ctx context.Context, refreshToken, audience string) (*LoginTokens, error) {
	newRefresh, userID, appID, err := s.RefreshRepo.Rotate(ctx, refreshToken, s.RefreshTTL)
	if err != nil {
		return nil, ErrInvalidRefresh
	}
	u, err := s.UserRepo.FindByID(ctx, appID, userID)
	if err != nil {
		return nil, err
	}
	if u.Disabled() {
		return nil, ErrAccountDisabled
	}
	access, err := s.Signer.Sign(u.ID, string(u.Role), audience)
	if err != nil {
		return nil, err
	}
	return &LoginTokens{AccessToken: access, RefreshToken: newRefresh, User: u}, nil
}

// Logout revokes the given refresh token. Idempotent.
func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	err := s.RefreshRepo.Revoke(ctx, refreshToken)
	if errors.Is(err, refresh.ErrNotFound) {
		return nil
	}
	return err
}

func (s *Service) issueTokens(ctx context.Context, appID uuid.UUID, u *model.User, audience string) (*LoginTokens, error) {
	access, err := s.Signer.Sign(u.ID, string(u.Role), audience)
	if err != nil {
		return nil, err
	}
	refreshPlain, err := s.RefreshRepo.Generate(ctx, appID, u.ID, s.RefreshTTL)
	if err != nil {
		return nil, err
	}
	return &LoginTokens{AccessToken: access, RefreshToken: refreshPlain, User: u}, nil
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./internal/service/auth/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/service/auth/
git commit -m "feat(service/auth): lift auth service with app_id scoping"
```

---

### Task 8: Create app-slug middleware

**Files:**
- Create: `internal/middleware/app.go`
- Create: `internal/middleware/auth.go`

Implement the hybrid routing middleware.

- [ ] **Step 1: Create middleware/app.go**

```go
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/repo/app"
)

const appKey = "app"

// AppSlugMiddleware resolves {slug} from the URL path to an app.Model.
// Rejects disabled apps with 403.
func AppSlugMiddleware(appRepo *app.Repo) gin.HandlerFunc {
	return func(c *gin.Context) {
		slug := c.Param("slug")
		if slug == "" {
			errs.Render(c, errs.New(http.StatusBadRequest, "MISSING_SLUG", "App slug is required"))
			c.Abort()
			return
		}

		a, err := appRepo.FindBySlug(c.Request.Context(), slug)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				errs.Render(c, errs.New(http.StatusNotFound, "APP_NOT_FOUND", "App not found"))
				c.Abort()
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error"))
			c.Abort()
			return
		}

		if a.DisabledAt != nil {
			errs.Render(c, errs.New(http.StatusForbidden, "APP_DISABLED", "App is disabled"))
			c.Abort()
			return
		}

		c.Set(appKey, a)
		c.Next()
	}
}

// GetApp retrieves the app.Model set by AppSlugMiddleware.
func GetApp(c *gin.Context) (*app.Model, bool) {
	v, ok := c.Get(appKey)
	if !ok {
		return nil, false
	}
	a, ok := v.(*app.Model)
	return a, ok
}
```

- [ ] **Step 2: Create middleware/auth.go**

```go
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/nathan-tsien/iam/internal/auth"
	"github.com/nathan-tsien/iam/internal/errs"
)

const authClaimsKey = "auth.claims"

// Auth parses a bearer token from the Authorization header and stores the
// verified Claims in the gin context. On any failure it emits 401 and aborts.
func Auth(signer *auth.Signer) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			errs.Render(c, errs.New(http.StatusUnauthorized, "UNAUTHENTICATED", "Missing bearer token"))
			c.Abort()
			return
		}
		token := strings.TrimPrefix(header, prefix)
		claims, err := signer.Verify(token)
		if err != nil {
			errs.Render(c, errs.New(http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired token").WithCause(err))
			c.Abort()
			return
		}
		c.Set(authClaimsKey, claims)
		c.Next()
	}
}

// GetAuthClaims retrieves Claims set by Auth, if any.
func GetAuthClaims(c *gin.Context) (*auth.Claims, bool) {
	v, ok := c.Get(authClaimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*auth.Claims)
	return claims, ok
}
```

- [ ] **Step 3: Update app repo to add FindBySlug**

The `internal/repo/app/repo.go` needs a `FindBySlug` method. Let me check if it exists.

Read: `internal/repo/app/repo.go`

- [ ] **Step 4: Add FindBySlug to app repo if missing**

```go
// FindBySlug returns the app with the given slug, or ErrNotFound.
func (r *Repo) FindBySlug(ctx context.Context, slug string) (*Model, error) {
	var m Model
	err := r.DB.WithContext(ctx).Where("slug = ?", slug).First(&m).Error
	if err != nil {
		return nil, err
	}
	return &m, nil
}
```

- [ ] **Step 5: Verify compilation**

Run: `go build ./internal/middleware/... ./internal/repo/app/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/middleware/ internal/repo/app/
git commit -m "feat(middleware): add app-slug and auth middleware"
```

---

## PR-3: HTTP Wiring

### Task 9: Create auth HTTP handlers

**Files:**
- Create: `internal/httpapi/auth.go`
- Create: `internal/httpapi/auth_test.go`

Wire auth service to HTTP endpoints.

- [ ] **Step 1: Create httpapi/auth.go**

```go
package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/nathan-tsien/iam/internal/errs"
	"github.com/nathan-tsien/iam/internal/middleware"
	"github.com/nathan-tsien/iam/internal/repo/user"
	"github.com/nathan-tsien/iam/internal/service/auth"
)

// RegisterAuth mounts auth endpoints on the router.
func RegisterAuth(r *gin.RouterGroup, authSvc *auth.Service) {
	r.POST("/auth/register", handleRegister(authSvc))
	r.POST("/auth/check-availability", handleCheckAvailability(authSvc))
	r.POST("/auth/otp/verify", handleVerifyOTP(authSvc))
	r.POST("/auth/login", handleLogin(authSvc))
	r.POST("/auth/refresh", handleRefresh(authSvc))
	r.POST("/auth/logout", handleLogout(authSvc))
}

func handleRegister(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email       string `json:"email" binding:"required"`
			Password    string `json:"password" binding:"required"`
			DisplayName string `json:"display_name" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		resp, err := authSvc.Register(c.Request.Context(), app.ID, req.Email, req.Password, req.DisplayName)
		if err != nil {
			switch e := err.(type) {
			case *auth.ErrWeakPassword:
				errs.Render(c, errs.New(http.StatusBadRequest, "WEAK_PASSWORD", "Password does not meet requirements").
					WithDetails(map[string]any{"failed_rules": e.FailedRules}))
			default:
				if err == user.ErrEmailTaken {
					errs.Render(c, errs.New(http.StatusConflict, "EMAIL_TAKEN", "Email already registered"))
					return
				}
				if err == auth.ErrDisplayNameTaken {
					errs.Render(c, errs.New(http.StatusConflict, "DISPLAY_NAME_TAKEN", "Display name already taken"))
					return
				}
				errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			}
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"user_id":      resp.UserID,
			"email":        resp.Email,
			"display_name": resp.DisplayName,
		})
	}
}

func handleCheckAvailability(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email       string `json:"email"`
			DisplayName string `json:"display_name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if req.Email == "" && req.DisplayName == "" {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", "At least one of email or display_name is required"))
			return
		}

		resp, err := authSvc.CheckAvailability(c.Request.Context(), app.ID, req.Email, req.DisplayName)
		if err != nil {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, resp)
	}
}

func handleVerifyOTP(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email string `json:"email" binding:"required"`
			Code  string `json:"code" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if err := authSvc.VerifyRegisterOTP(c.Request.Context(), app.ID, req.Email, req.Code); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_OTP", "Invalid or expired OTP code"))
			return
		}

		c.JSON(http.StatusOK, gin.H{"verified": true})
	}
}

func handleLogin(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			Email    string `json:"email" binding:"required"`
			Password string `json:"password" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		tokens, err := authSvc.Login(c.Request.Context(), app.ID, req.Email, req.Password, app.JWTAudience)
		if err != nil {
			switch err {
			case auth.ErrInvalidCredentials:
				errs.Render(c, errs.New(http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password"))
			case auth.ErrEmailNotVerified:
				errs.Render(c, errs.New(http.StatusForbidden, "EMAIL_NOT_VERIFIED", "Email not verified"))
			case auth.ErrAccountDisabled:
				errs.Render(c, errs.New(http.StatusForbidden, "ACCOUNT_DISABLED", "Account is disabled"))
			default:
				errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"user_id":       tokens.User.ID,
			"email":         tokens.User.Email,
			"role":          tokens.User.Role,
		})
	}
}

func handleRefresh(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		app, ok := middleware.GetApp(c)
		if !ok {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "App not in context"))
			return
		}

		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		tokens, err := authSvc.Refresh(c.Request.Context(), req.RefreshToken, app.JWTAudience)
		if err != nil {
			if err == auth.ErrInvalidRefresh {
				errs.Render(c, errs.New(http.StatusUnauthorized, "INVALID_REFRESH", "Invalid or expired refresh token"))
				return
			}
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"user_id":       tokens.User.ID,
			"email":         tokens.User.Email,
			"role":          tokens.User.Role,
		})
	}
}

func handleLogout(authSvc *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			errs.Render(c, errs.New(http.StatusBadRequest, "INVALID_REQUEST", err.Error()))
			return
		}

		if err := authSvc.Logout(c.Request.Context(), req.RefreshToken); err != nil {
			errs.Render(c, errs.New(http.StatusInternalServerError, "INTERNAL", "Internal server error").WithCause(err))
			return
		}

		c.JSON(http.StatusOK, gin.H{"logged_out": true})
	}
}
```

- [ ] **Step 2: Verify compilation**

Run: `go build ./internal/httpapi/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/httpapi/
git commit -m "feat(httpapi): add auth HTTP handlers"
```

---

### Task 10: Wire cmd/api/main.go

**Files:**
- Modify: `cmd/api/main.go`

Add auth service wiring to the API server.

- [ ] **Step 1: Read current main.go**

Read: `cmd/api/main.go`

- [ ] **Step 2: Update main.go with auth wiring**

Add imports and wiring for:
- auth.Signer (JWT)
- user.Repo
- refresh.Repo
- otp.Service
- auth.Service
- middleware.AppSlugMiddleware
- httpapi.RegisterAuth

- [ ] **Step 3: Verify compilation**

Run: `make build`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add cmd/api/main.go
git commit -m "feat(api): wire auth service and routes"
```

---

### Task 11: Update tracker and run final verification

**Files:**
- Modify: `docs/migration/tracker.md`

- [ ] **Step 1: Update tracker**

Mark P1-T4 and P1-T5 as in-progress or done based on completion.

- [ ] **Step 2: Run full test suite**

Run: `make test`
Expected: PASS

- [ ] **Step 3: Run linter**

Run: `make lint`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add docs/migration/tracker.md
git commit -m "docs(tracker): update Wave 2 progress"
```

---

## Exit Criteria Verification

- [ ] `make lint` passes
- [ ] `make test` passes
- [ ] `curl -X POST http://localhost:8090/v1/apps/demo/auth/register -d '{"email":"test@example.com","password":"Test1234!","display_name":"Test User"}'` returns 201
- [ ] `curl -X POST http://localhost:8090/v1/apps/demo/auth/login -d '{"email":"test@example.com","password":"Test1234!"}'` returns 200 with tokens
- [ ] Token for `demo` rejected when used against another app slug
