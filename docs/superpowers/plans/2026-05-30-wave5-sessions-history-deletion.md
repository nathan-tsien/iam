# Wave 5: Sessions, Login History, Account Deletion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Self-service session management (list/revoke), login history, and account deletion with soft-delete + PII anonymization.

**Architecture:** New `sessions` service handles session listing/revocation and login history. `userprofile` service extended with `DeleteAccount`. Repo layer adds `SoftDelete`, `ListActive`, `RevokeByID`, `ListByUser`. OpenAPI spec extended with 5 new endpoints, code regenerated.

**Tech Stack:** Go, GORM, Gin, oapi-codegen, bcrypt, PostgreSQL

---

### Task 1: User model + repo — Deleted helper and deleted_at filtering

**Files:**
- Modify: `internal/model/user.go`
- Modify: `internal/repo/user/user.go`

- [ ] **Step 1: Add `Deleted()` helper to User model**

Add after line 36 in `internal/model/user.go`:

```go
func (u *User) Deleted() bool { return u.DeletedAt != nil }
```

- [ ] **Step 2: Add `deleted_at IS NULL` filter to FindByEmail**

In `internal/repo/user/user.go`, modify `FindByEmail` (line 68-77). Add `AND deleted_at IS NULL` to the WHERE clause:

```go
func (r *Repo) FindByEmail(ctx context.Context, appID uuid.UUID, email string) (*model.User, error) {
	var u model.User
	err := r.DB.WithContext(ctx).
		Where("app_id = ? AND email_lower = ? AND deleted_at IS NULL", appID, strings.ToLower(email)).
		First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &u, err
}
```

- [ ] **Step 3: Add `deleted_at IS NULL` filter to FindByID**

In `internal/repo/user/user.go`, modify `FindByID` (line 79-89):

```go
func (r *Repo) FindByID(ctx context.Context, appID, id uuid.UUID) (*model.User, error) {
	var u model.User
	err := r.DB.WithContext(ctx).
		Where("app_id = ? AND id = ? AND deleted_at IS NULL", appID, id).
		First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return &u, err
}
```

- [ ] **Step 4: Add SoftDelete method**

Add at the end of `internal/repo/user/user.go`:

```go
// SoftDelete marks a user as deleted and anonymizes PII. Idempotent.
func (r *Repo) SoftDelete(ctx context.Context, appID, id uuid.UUID) error {
	res := r.DB.WithContext(ctx).Model(&model.User{}).
		Where("app_id = ? AND id = ? AND deleted_at IS NULL", appID, id).
		Updates(map[string]any{
			"deleted_at":   gorm.Expr("NOW()"),
			"disabled_at":  gorm.Expr("NOW()"),
			"email":        fmt.Sprintf("deleted-%s@invalid", id),
			"email_lower":  fmt.Sprintf("deleted-%s@invalid", id),
			"display_name": nil,
			"avatar_url":   nil,
			"updated_at":   gorm.Expr("NOW()"),
		})
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return res.Error
}
```

- [ ] **Step 5: Run tests**

```bash
make test
```

Expected: All existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/model/user.go internal/repo/user/user.go
git commit -m "feat(repo): add SoftDelete and deleted_at filtering for users"
```

---

### Task 2: Refresh Token struct — add missing DB columns

**Files:**
- Modify: `internal/repo/refresh/refresh.go`
- Modify: `internal/service/auth/auth.go`

The refresh_tokens table has columns `device_label`, `user_agent`, `ip`, `last_seen_at` that are not mapped in the Go Token struct. These are needed for session display.

- [ ] **Step 1: Add missing fields to Token struct**

In `internal/repo/refresh/refresh.go`, replace the Token struct (line 19-27):

```go
// Token mirrors iam.refresh_tokens.
type Token struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	UserID      uuid.UUID  `gorm:"type:uuid;not null"`
	AppID       uuid.UUID  `gorm:"type:uuid;not null;index"`
	TokenHash   string     `gorm:"not null"`
	IssuedAt    time.Time  `gorm:"autoCreateTime"`
	ExpiresAt   time.Time  `gorm:"not null"`
	RevokedAt   *time.Time
	ReplacedBy  *uuid.UUID `gorm:"type:uuid"`
	DeviceLabel *string
	UserAgent   string
	IP          string
	LastSeenAt  *time.Time
	CreatedAt   time.Time  `gorm:"autoCreateTime"`
}
```

- [ ] **Step 2: Update Generate to accept optional metadata**

Replace the `Generate` method (line 38-53):

```go
// TokenMetadata holds optional session metadata for a refresh token.
type TokenMetadata struct {
	DeviceLabel string
	UserAgent   string
	IP          string
}

// Generate issues a new refresh token for userID within an app.
func (r *Repo) Generate(ctx context.Context, appID, userID uuid.UUID, ttl time.Duration, meta ...TokenMetadata) (string, error) {
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
	if len(meta) > 0 {
		row.DeviceLabel = nilToStringPtr(meta[0].DeviceLabel)
		row.UserAgent = meta[0].UserAgent
		row.IP = meta[0].IP
	}
	if err := r.DB.WithContext(ctx).Create(row).Error; err != nil {
		return "", err
	}
	return plain, nil
}

func nilToStringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
```

- [ ] **Step 3: Update Rotate to carry forward metadata**

In the `Rotate` method, after line 113 (`newPlain = nPlain`), update the new token creation to carry forward UserAgent and IP from the old token:

```go
			return tx.Create(&Token{
				UserID:    old.UserID,
				AppID:     old.AppID,
				TokenHash: hashToken(nPlain),
				ExpiresAt: now.Add(ttl),
				UserAgent: old.UserAgent,
				IP:        old.IP,
			}).Error
```

- [ ] **Step 4: Update auth service Login to pass metadata**

In `internal/service/auth/auth.go`, update the `issueTokens` call in `Login` (line 217):

```go
	return s.issueTokens(ctx, appID, u, audience, ip, userAgent)
```

Update `issueTokens` signature and body (line 310-320):

```go
func (s *Service) issueTokens(ctx context.Context, appID uuid.UUID, u *model.User, audience, ip, userAgent string) (*LoginTokens, error) {
	access, err := s.Signer.Sign(u.ID, string(u.Role), audience)
	if err != nil {
		return nil, err
	}
	refreshPlain, err := s.RefreshRepo.Generate(ctx, appID, u.ID, s.RefreshTTL, refresh.TokenMetadata{
		UserAgent: userAgent,
		IP:        ip,
	})
	if err != nil {
		return nil, err
	}
	return &LoginTokens{AccessToken: access, RefreshToken: refreshPlain, User: u}, nil
}
```

- [ ] **Step 5: Update auth service Refresh to pass metadata**

In `internal/service/auth/auth.go`, `Refresh` method (line 221-238) — no changes needed since Rotate carries forward metadata.

- [ ] **Step 6: Run tests**

```bash
make test
```

Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add internal/repo/refresh/refresh.go internal/service/auth/auth.go
git commit -m "feat(refresh): add session metadata fields to Token struct"
```

---

### Task 3: Refresh token repo — ListActive, RevokeByID, RevokeAllForUserInApp, TokenHash

**Files:**
- Modify: `internal/repo/refresh/refresh.go`

- [ ] **Step 1: Add TokenHash helper**

This exports the hashing logic so the HTTP layer can hash the client's refresh token for `is_current` comparison. Add after `hashToken`:

```go
// TokenHash returns the SHA-256 hash of a plaintext token.
func TokenHash(plain string) string {
	return hashToken(plain)
}
```

- [ ] **Step 2: Add ListActive method**

Add after `RevokeAllForUser`:

```go
// ListActive returns non-expired, non-revoked refresh tokens for a user within an app.
func (r *Repo) ListActive(ctx context.Context, userID, appID uuid.UUID) ([]Token, error) {
	var tokens []Token
	err := r.DB.WithContext(ctx).
		Where("user_id = ? AND app_id = ? AND revoked_at IS NULL AND expires_at > NOW()", userID, appID).
		Order("last_seen_at DESC NULLS LAST, created_at DESC").
		Find(&tokens).Error
	return tokens, err
}
```

- [ ] **Step 3: Add RevokeByID method**

Add after `Revoke`:

```go
// RevokeByID marks a specific token as revoked by its ID.
// Ownership check: only revokes if the token belongs to the given user.
// Returns changed=false if not found or already revoked.
func (r *Repo) RevokeByID(ctx context.Context, id, userID uuid.UUID) (bool, error) {
	now := time.Now()
	res := r.DB.WithContext(ctx).Model(&Token{}).
		Where("id = ? AND user_id = ? AND revoked_at IS NULL", id, userID).
		Update("revoked_at", now)
	return res.RowsAffected > 0, res.Error
}
```

- [ ] **Step 4: Add RevokeAllForUserInApp method**

Add after `RevokeAllForUser`:

```go
// RevokeAllForUserInApp revokes all active refresh tokens for a user within a specific app.
func (r *Repo) RevokeAllForUserInApp(ctx context.Context, userID, appID uuid.UUID) error {
	res := r.DB.WithContext(ctx).Model(&Token{}).
		Where("user_id = ? AND app_id = ? AND revoked_at IS NULL", userID, appID).
		Update("revoked_at", time.Now().UTC())
	return res.Error
}
```

- [ ] **Step 5: Run tests**

```bash
make test
```

Expected: All existing tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/repo/refresh/refresh.go
git commit -m "feat(repo): add ListActive, RevokeByID, RevokeAllForUserInApp, TokenHash"
```

---

### Task 4: Login event repo — ListByUser with cursor pagination

**Files:**
- Modify: `internal/repo/loginevent/repo.go`

- [ ] **Step 1: Add ListByUser method**

Add after `Record` in `internal/repo/loginevent/repo.go`:

```go
// ListByUser returns login events for a user within an app, paginated by occurred_at cursor.
// Cursor is the occurred_at timestamp of the last item; pass zero time for the first page.
// Returns events and the cursor for the next page (nil if no more).
func (r *Repo) ListByUser(ctx context.Context, userID, appID uuid.UUID, cursor time.Time, limit int) ([]Event, *time.Time, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	q := r.DB.WithContext(ctx).
		Where("user_id = ? AND app_id = ?", userID, appID)

	if !cursor.IsZero() {
		q = q.Where("occurred_at < ?", cursor)
	}

	var events []Event
	err := q.Order("occurred_at DESC").Limit(limit + 1).Find(&events).Error
	if err != nil {
		return nil, nil, err
	}

	var nextCursor *time.Time
	if len(events) > limit {
		nextCursor = &events[limit-1].OccurredAt
		events = events[:limit]
	}

	return events, nextCursor, nil
}
```

- [ ] **Step 2: Run tests**

```bash
make test
```

Expected: All tests pass.

- [ ] **Step 3: Commit**

```bash
git add internal/repo/loginevent/repo.go
git commit -m "feat(repo): add ListByUser with cursor pagination for login history"
```

---

### Task 5: Sessions service

**Files:**
- Create: `internal/service/sessions/service.go`

- [ ] **Step 1: Create sessions service**

```go
package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nathan-tsien/iam/internal/repo/loginevent"
	"github.com/nathan-tsien/iam/internal/repo/refresh"
)

var ErrNotFound = errors.New("session not found")

type SessionInfo struct {
	ID          uuid.UUID
	DeviceLabel *string
	UserAgent   string
	IP          string
	CreatedAt   time.Time
	LastSeenAt  *time.Time
	IsCurrent   bool
}

type LoginEvent struct {
	ID         uuid.UUID
	Kind       string
	IP         string
	UserAgent  string
	OccurredAt time.Time
}

type Deps struct {
	RefreshRepo    *refresh.Repo
	LoginEventRepo *loginevent.Repo
}

type Service struct {
	Deps
}

func NewService(d Deps) *Service { return &Service{Deps: d} }

// ListSessions returns active sessions for a user within an app.
// currentTokenHash is the hash of the requesting client's refresh token;
// the matching session gets IsCurrent=true. Pass empty string to skip.
func (s *Service) ListSessions(ctx context.Context, userID, appID uuid.UUID, currentTokenHash string) ([]SessionInfo, error) {
	tokens, err := s.RefreshRepo.ListActive(ctx, userID, appID)
	if err != nil {
		return nil, err
	}

	sessions := make([]SessionInfo, len(tokens))
	for i, t := range tokens {
		sessions[i] = SessionInfo{
			ID:          t.ID,
			DeviceLabel: t.DeviceLabel,
			UserAgent:   t.UserAgent,
			IP:          t.IP,
			CreatedAt:   t.IssuedAt,
			LastSeenAt:  t.LastSeenAt,
			IsCurrent:   currentTokenHash != "" && t.TokenHash == currentTokenHash,
		}
	}

	return sessions, nil
}

// RevokeSession revokes a specific session by ID.
// Returns ErrNotFound if the session doesn't exist or doesn't belong to the user.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID uuid.UUID) error {
	changed, err := s.RefreshRepo.RevokeByID(ctx, sessionID, userID)
	if err != nil {
		return err
	}
	if !changed {
		return ErrNotFound
	}
	return nil
}

// RevokeAllSessions revokes all sessions for a user within an app.
func (s *Service) RevokeAllSessions(ctx context.Context, userID, appID uuid.UUID) error {
	return s.RefreshRepo.RevokeAllForUserInApp(ctx, userID, appID)
}

// LoginHistory returns paginated login events for a user within an app.
func (s *Service) LoginHistory(ctx context.Context, userID, appID uuid.UUID, cursor time.Time, limit int) ([]LoginEvent, *time.Time, error) {
	events, nextCursor, err := s.LoginEventRepo.ListByUser(ctx, userID, appID, cursor, limit)
	if err != nil {
		return nil, nil, err
	}

	result := make([]LoginEvent, len(events))
	for i, e := range events {
		result[i] = LoginEvent{
			ID:         e.ID,
			Kind:       e.Kind,
			IP:         e.IP,
			UserAgent:  e.UserAgent,
			OccurredAt: e.OccurredAt,
		}
	}

	return result, nextCursor, nil
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/service/sessions/...
```

Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add internal/service/sessions/
git commit -m "feat(service): add sessions service for session management and login history"
```

---

### Task 6: Userprofile service — DeleteAccount

**Files:**
- Modify: `internal/service/userprofile/service.go`

- [ ] **Step 1: Add dependencies and DeleteAccount method**

Replace the contents of `internal/service/userprofile/service.go`:

```go
package userprofile

import (
	"context"
	"errors"

	"github.com/google/uuid"

	pkgauth "github.com/nathan-tsien/iam/internal/auth"
	"github.com/nathan-tsien/iam/internal/model"
	"github.com/nathan-tsien/iam/internal/repo/auditlog"
	"github.com/nathan-tsien/iam/internal/repo/refresh"
	userrepo "github.com/nathan-tsien/iam/internal/repo/user"
)

var ErrInvalidPassword = errors.New("invalid password")

type Deps struct {
	UserRepo    *userrepo.Repo
	RefreshRepo *refresh.Repo
	AuditRepo   *auditlog.Repo
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

// DeleteAccount soft-deletes the user, anonymizes PII, and revokes all sessions.
// Verifies password before proceeding. Returns ErrInvalidPassword on mismatch.
func (s *Service) DeleteAccount(ctx context.Context, appID, userID uuid.UUID, password string) error {
	u, err := s.UserRepo.FindByID(ctx, appID, userID)
	if err != nil {
		return err
	}

	if err := pkgauth.VerifyPassword(u.PasswordHash, password); err != nil {
		return ErrInvalidPassword
	}

	if err := s.UserRepo.SoftDelete(ctx, appID, userID); err != nil {
		return err
	}

	// Revoke all sessions
	_ = s.RefreshRepo.RevokeAllForUserInApp(ctx, userID, appID)

	// Write audit log (best-effort)
	if s.AuditRepo != nil {
		go func() {
			_ = s.AuditRepo.Record(context.Background(), &auditlog.Entry{
				AppID:    appID,
				ActorID:  &userID,
				TargetID: &userID,
				Action:   "user.deleted",
			})
		}()
	}

	return nil
}
```

- [ ] **Step 2: Verify compilation**

```bash
go build ./internal/service/userprofile/...
```

Expected: No errors.

- [ ] **Step 3: Commit**

```bash
git add internal/service/userprofile/service.go
git commit -m "feat(service): add DeleteAccount to userprofile with PII anonymization"
```

---

### Task 7: OpenAPI spec — add session, login-history, delete-me endpoints

**Files:**
- Modify: `api/openapi.yaml`

- [ ] **Step 1: Add new paths to openapi.yaml**

Add the following paths after the `/me` path block (after line 288) and before `/users`:

```yaml
  /me/sessions:
    get:
      operationId: getMeSessions
      summary: List active sessions
      tags: [profile]
      security:
        - BearerAuth: []
      parameters:
        - name: X-Session-Token
          in: header
          description: Current refresh token (used to identify the current session)
          required: false
          schema:
            type: string
      responses:
        "200":
          description: Active sessions
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/SessionsResponse"
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "500":
          $ref: "#/components/responses/InternalError"
    delete:
      operationId: deleteMeSessions
      summary: Revoke all sessions
      tags: [profile]
      security:
        - BearerAuth: []
      responses:
        "204":
          description: All sessions revoked
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "500":
          $ref: "#/components/responses/InternalError"

  /me/sessions/{id}:
    delete:
      operationId: deleteMeSession
      summary: Revoke a specific session
      tags: [profile]
      security:
        - BearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          description: Session (refresh token) UUID
          schema:
            type: string
            format: uuid
      responses:
        "204":
          description: Session revoked
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "404":
          $ref: "#/components/responses/NotFound"
        "500":
          $ref: "#/components/responses/InternalError"

  /me/login-history:
    get:
      operationId: getMeLoginHistory
      summary: Paginated login history
      tags: [profile]
      security:
        - BearerAuth: []
      parameters:
        - name: cursor
          in: query
          description: Cursor from previous response (ISO 8601 timestamp)
          schema:
            type: string
            format: date-time
        - name: limit
          in: query
          description: Number of results per page (1-100, default 20)
          schema:
            type: integer
            minimum: 1
            maximum: 100
            default: 20
      responses:
        "200":
          description: Login history
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/LoginHistoryResponse"
        "401":
          $ref: "#/components/responses/Unauthenticated"
        "500":
          $ref: "#/components/responses/InternalError"

  /me/delete:
    post:
      operationId: deleteMe
      summary: Delete own account
      tags: [profile]
      security:
        - BearerAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/DeleteMeRequest"
      responses:
        "204":
          description: Account deleted
        "400":
          $ref: "#/components/responses/BadRequest"
        "401":
          description: Invalid password
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/Error"
        "500":
          $ref: "#/components/responses/InternalError"
```

- [ ] **Step 2: Add new schemas**

Add after `EnabledResponse` (after line 675):

```yaml
    Session:
      type: object
      required: [id, created_at, is_current]
      properties:
        id:
          type: string
          format: uuid
        device_label:
          type: string
          nullable: true
        user_agent:
          type: string
          nullable: true
        ip:
          type: string
          nullable: true
        created_at:
          type: string
          format: date-time
        last_seen_at:
          type: string
          format: date-time
          nullable: true
        is_current:
          type: boolean

    SessionsResponse:
      type: object
      required: [sessions]
      properties:
        sessions:
          type: array
          items:
            $ref: "#/components/schemas/Session"

    LoginEventSchema:
      type: object
      required: [id, kind, occurred_at]
      properties:
        id:
          type: string
          format: uuid
        kind:
          type: string
        ip:
          type: string
          nullable: true
        user_agent:
          type: string
          nullable: true
        occurred_at:
          type: string
          format: date-time

    LoginHistoryResponse:
      type: object
      required: [events]
      properties:
        events:
          type: array
          items:
            $ref: "#/components/schemas/LoginEventSchema"
        next_cursor:
          type: string
          format: date-time
          nullable: true

    DeleteMeRequest:
      type: object
      required: [password]
      properties:
        password:
          type: string
          format: password
```

- [ ] **Step 3: Regenerate code**

```bash
go generate ./api/...
```

Expected: `api/iam.gen.go` is regenerated with new types and interfaces.

- [ ] **Step 4: Verify compilation fails**

```bash
go build ./...
```

Expected: Compilation errors because `StrictServer` doesn't implement the new interface methods yet.

- [ ] **Step 5: Commit**

```bash
git add api/openapi.yaml api/iam.gen.go
git commit -m "feat(api): add sessions, login-history, delete-me endpoints to OpenAPI spec"
```

---

### Task 8: HTTP handlers — implement new strict handler methods

**Files:**
- Modify: `internal/httpapi/strict.go`

- [ ] **Step 1: Add imports, SessionsSvc field, and update middleware maps**

In `internal/httpapi/strict.go`:

1. Add imports:
```go
"github.com/nathan-tsien/iam/internal/repo/refresh"
"github.com/nathan-tsien/iam/internal/service/sessions"
```

2. Add `SessionsSvc` field to `StrictServer`:
```go
type StrictServer struct {
	AuthSvc     *auth.Service
	ProfileSvc  *userprofile.Service
	AdminSvc    *useradmin.Service
	SessionsSvc *sessions.Service
}
```

3. Add new operations to `authRequiredOps`:
```go
var authRequiredOps = map[string]bool{
	"GetMe":                true,
	"UpdateMe":             true,
	"ListUsers":            true,
	"GetUser":              true,
	"DisableUser":          true,
	"EnableUser":           true,
	"TriggerPasswordReset": true,
	"GetMeSessions":        true,
	"DeleteMeSession":      true,
	"DeleteMeSessions":     true,
	"GetMeLoginHistory":    true,
	"DeleteMe":             true,
}
```

4. Add rate limit for `DeleteMe`:
```go
"DeleteMe": {Max: 5, Window: time.Minute},
```

- [ ] **Step 2: Add GetMeSessions handler**

Add after `UpdateMe` handler:

```go
func (s *StrictServer) GetMeSessions(ctx context.Context, request api.GetMeSessionsRequestObject) (api.GetMeSessionsResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}
	claims, ok := middleware.GetAuthClaims(gc)
	if !ok {
		return nil, errors.New("auth claims not in context")
	}

	var currentHash string
	if token := request.Params.XSessionToken; token != nil {
		currentHash = refresh.TokenHash(*token)
	}

	sess, err := s.SessionsSvc.ListSessions(ctx, claims.UserID(), app.ID, currentHash)
	if err != nil {
		return nil, err
	}

	items := make([]api.Session, len(sess))
	for i, s := range sess {
		item := api.Session{
			Id:        openapi_types.UUID(s.ID),
			CreatedAt: s.CreatedAt,
			IsCurrent: s.IsCurrent,
		}
		if s.DeviceLabel != nil {
			item.DeviceLabel = s.DeviceLabel
		}
		if s.UserAgent != "" {
			item.UserAgent = &s.UserAgent
		}
		if s.IP != "" {
			item.Ip = &s.IP
		}
		if s.LastSeenAt != nil {
			item.LastSeenAt = s.LastSeenAt
		}
		items[i] = item
	}

	return api.GetMeSessions200JSONResponse{Sessions: items}, nil
}
```

- [ ] **Step 3: Add DeleteMeSession handler**

```go
func (s *StrictServer) DeleteMeSession(ctx context.Context, request api.DeleteMeSessionRequestObject) (api.DeleteMeSessionResponseObject, error) {
	gc := ctx.(*gin.Context)
	claims, ok := middleware.GetAuthClaims(gc)
	if !ok {
		return nil, errors.New("auth claims not in context")
	}

	if err := s.SessionsSvc.RevokeSession(ctx, claims.UserID(), request.Id); err != nil {
		if errors.Is(err, sessions.ErrNotFound) {
			return api.DeleteMeSession404JSONResponse{
				NotFoundJSONResponse: api.NotFoundJSONResponse{
					Code:    "SESSION_NOT_FOUND",
					Message: "Session not found",
				},
			}, nil
		}
		return nil, err
	}

	return api.DeleteMeSession204Response{}, nil
}
```

- [ ] **Step 4: Add DeleteMeSessions handler**

```go
func (s *StrictServer) DeleteMeSessions(ctx context.Context, request api.DeleteMeSessionsRequestObject) (api.DeleteMeSessionsResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}
	claims, ok := middleware.GetAuthClaims(gc)
	if !ok {
		return nil, errors.New("auth claims not in context")
	}

	if err := s.SessionsSvc.RevokeAllSessions(ctx, claims.UserID(), app.ID); err != nil {
		return nil, err
	}

	return api.DeleteMeSessions204Response{}, nil
}
```

- [ ] **Step 5: Add GetMeLoginHistory handler**

```go
func (s *StrictServer) GetMeLoginHistory(ctx context.Context, request api.GetMeLoginHistoryRequestObject) (api.GetMeLoginHistoryResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}
	claims, ok := middleware.GetAuthClaims(gc)
	if !ok {
		return nil, errors.New("auth claims not in context")
	}

	limit := 20
	if request.Params.Limit != nil && *request.Params.Limit > 0 && *request.Params.Limit <= 100 {
		limit = *request.Params.Limit
	}

	var cursor time.Time
	if request.Params.Cursor != nil {
		cursor = *request.Params.Cursor
	}

	events, nextCursor, err := s.SessionsSvc.LoginHistory(ctx, claims.UserID(), app.ID, cursor, limit)
	if err != nil {
		return nil, err
	}

	items := make([]api.LoginEventSchema, len(events))
	for i, e := range events {
		item := api.LoginEventSchema{
			Id:         openapi_types.UUID(e.ID),
			Kind:       e.Kind,
			OccurredAt: e.OccurredAt,
		}
		if e.IP != "" {
			item.Ip = &e.IP
		}
		if e.UserAgent != "" {
			item.UserAgent = &e.UserAgent
		}
		items[i] = item
	}

	resp := api.GetMeLoginHistory200JSONResponse{Events: items}
	if nextCursor != nil {
		resp.NextCursor = nextCursor
	}
	return resp, nil
}
```

- [ ] **Step 6: Add DeleteMe handler**

```go
func (s *StrictServer) DeleteMe(ctx context.Context, request api.DeleteMeRequestObject) (api.DeleteMeResponseObject, error) {
	gc := ctx.(*gin.Context)
	app, ok := middleware.GetApp(gc)
	if !ok {
		return nil, errors.New("app not in context")
	}
	claims, ok := middleware.GetAuthClaims(gc)
	if !ok {
		return nil, errors.New("auth claims not in context")
	}

	if err := s.ProfileSvc.DeleteAccount(ctx, app.ID, claims.UserID(), request.Body.Password); err != nil {
		if errors.Is(err, userprofile.ErrInvalidPassword) {
			return api.DeleteMe401JSONResponse{
				Code:    "INVALID_PASSWORD",
				Message: "Invalid password",
			}, nil
		}
		return nil, err
	}

	return api.DeleteMe204Response{}, nil
}
```

- [ ] **Step 7: Verify compilation**

```bash
go build ./...
```

Expected: No errors.

- [ ] **Step 8: Commit**

```bash
git add internal/httpapi/strict.go
git commit -m "feat(httpapi): implement session, login-history, delete-me handlers"
```

---

### Task 9: Wiring — update main.go

**Files:**
- Modify: `cmd/api/main.go`

- [ ] **Step 1: Add sessions service wiring**

In `cmd/api/main.go`:

1. Add import:
```go
sessionssvc "github.com/nathan-tsien/iam/internal/service/sessions"
```

2. After `adminSvc` creation (line 121), add:
```go
	sessionsSvc := sessionssvc.NewService(sessionssvc.Deps{
		RefreshRepo:    refreshRepo,
		LoginEventRepo: loginEventRepo,
	})
```

3. Update `profileSvc` creation to include new dependencies:
```go
	profileSvc := userprofilesvc.NewService(userprofilesvc.Deps{
		UserRepo:    userRepo,
		RefreshRepo: refreshRepo,
		AuditRepo:   auditRepo,
	})
```

4. Update `strictServer` creation:
```go
	strictServer := &httpapi.StrictServer{
		AuthSvc:     authSvc,
		ProfileSvc:  profileSvc,
		AdminSvc:    adminSvc,
		SessionsSvc: sessionsSvc,
	}
```

- [ ] **Step 2: Run full build and tests**

```bash
make build && make lint && make test
```

Expected: All pass.

- [ ] **Step 3: Commit**

```bash
git add cmd/api/main.go
git commit -m "feat(api): wire sessions service and updated userprofile deps"
```

---

### Task 10: Update operation map tests

**Files:**
- Modify: `internal/httpapi/strict_test.go`

- [ ] **Step 1: Update authRequiredOps test**

Update `TestAuthRequiredOpsContent`:

```go
func TestAuthRequiredOpsContent(t *testing.T) {
	expected := map[string]bool{
		"GetMe":                true,
		"UpdateMe":             true,
		"ListUsers":            true,
		"GetUser":              true,
		"DisableUser":          true,
		"EnableUser":           true,
		"TriggerPasswordReset": true,
		"GetMeSessions":        true,
		"DeleteMeSession":      true,
		"DeleteMeSessions":     true,
		"GetMeLoginHistory":    true,
		"DeleteMe":             true,
	}
	for op, want := range expected {
		if got := authRequiredOps[op]; got != want {
			t.Errorf("authRequiredOps[%q] = %v, want %v", op, got, want)
		}
	}
	for op := range authRequiredOps {
		if _, ok := expected[op]; !ok {
			t.Errorf("authRequiredOps contains unexpected operation %q", op)
		}
	}
}
```

- [ ] **Step 2: Update rateLimitOps test**

Update `TestRateLimitOpsConfig`:

```go
func TestRateLimitOpsConfig(t *testing.T) {
	tests := []struct {
		op     string
		max    int64
		window time.Duration
	}{
		{"Register", 3, time.Minute},
		{"Login", 5, time.Minute},
		{"ForgotPassword", 3, time.Minute},
		{"ListUsers", 100, time.Minute},
		{"DeleteMe", 5, time.Minute},
	}

	for _, tt := range tests {
		cfg, ok := rateLimitOps[tt.op]
		if !ok {
			t.Errorf("rateLimitOps missing operation %q", tt.op)
			continue
		}
		if cfg.Max != tt.max {
			t.Errorf("rateLimitOps[%q].Max = %d, want %d", tt.op, cfg.Max, tt.max)
		}
		if cfg.Window != tt.window {
			t.Errorf("rateLimitOps[%q].Window = %v, want %v", tt.op, cfg.Window, tt.window)
		}
	}

	expectedOps := map[string]bool{
		"Register": true, "Login": true, "ForgotPassword": true, "ListUsers": true, "DeleteMe": true,
	}
	for op := range rateLimitOps {
		if !expectedOps[op] {
			t.Errorf("rateLimitOps contains unexpected operation %q", op)
		}
	}
}
```

- [ ] **Step 3: Run tests**

```bash
make test
```

Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add internal/httpapi/strict_test.go
git commit -m "test(httpapi): update operation map tests for wave 5 endpoints"
```

---

### Task 11: Update tracker

**Files:**
- Modify: `docs/migration/tracker.md`

- [ ] **Step 1: Mark P1-T7 as done**

Update the P1-T7 entry in `docs/migration/tracker.md`:

```
- [x] **P1-T7** sessions-and-account — Sessions list/revoke, login history, self-delete (soft + anonymize + webhook)
  - status: done
  - blocked-by: ·
  - started: 2026-05-30
  - finished: 2026-05-30
  - commit: <hash>
  - PR: ·
  - note: `login_events` writes are non-blocking. Webhook outbox deferred to Wave 6.
```

Also update the "Current position" section:

```
Done:  Waves 1-5 + OpenAPI codegen migration
Next:  Wave 6 -- webhook outbox, dispatch worker
```

- [ ] **Step 2: Commit**

```bash
git add docs/migration/tracker.md
git commit -m "docs(tracker): mark P1-T7 sessions-and-account complete"
```
