---
name: wave4-self-service-admin
overview: Wave 4 design - self-service /me profile, per-app admin user management, audit logging
status: approved
---

# Wave 4: Self-service and Per-app Admin Design

## Goal

`/me` self-service profile, avatar URL, and app-scoped admin user management with audit logging.

## Design Decisions

### Avatar: URL-only (not presigned URL)

Research showed Auth0, Firebase, Supabase, and Keycloak all use URL-only pattern — the auth service stores an `avatar_url` string, image hosting is delegated to consumer applications. Clerk and Okta (new) use presigned URL but they are full identity platforms. For a focused IAM service, URL-only keeps scope clean. The `STORAGE_*` env vars in `.env.example` are reserved for future optional extension.

### RBAC: JWT role + DB verification

Admin middleware checks `claims.Role == "admin"` from JWT, then verifies against DB that the user still exists, is not disabled, and still has admin role. This prevents stale-token exploitation after admin demotion or account disable.

### Admin endpoints: POST action pattern

POST action endpoints (`/users/:id/disable`, `/users/:id/enable`, `/users/:id/trigger-password-reset`) are used instead of PATCH field updates. Rationale: all three trigger side effects (audit logs, session revocation, email dispatch). Consistent with Clerk's pattern. Maps cleanly to webhook event names (`user.disabled`, `user.enabled`).

### Last admin protection

Prevent disabling the last active admin in an app. Count admins before disable; if count would drop to 0, reject with `LAST_ADMIN` error. Self-disable is allowed if other admins exist.

### Pagination: cursor-based with composite key

Use `(created_at, id)` composite cursor for deterministic ordering. Auth0, Clerk, and Firebase all use cursor-based pagination. Composite key prevents skip/duplicate on concurrent writes.

### Search: ILIKE (pg_trgm deferred)

Plain `ILIKE` on `email_lower` and `display_name`. Adequate for Phase 1 scale. `pg_trgm` + GIN index can be added via migration when approaching 100K rows per app.

### Audit logging: synchronous best-effort

Same pattern as Wave 3 `login_events` — write synchronously but don't fail the HTTP request if audit INSERT fails. Log the error instead. Async via buffered channel deferred until evidence of bottleneck.

### Rate limiting on admin endpoints

100 requests/min per admin user (using JWT subject as rate limit key). Protects against compromised admin token abuse. Uses existing `RateLimit` middleware.

## Modules

### 1. userprofile Service + /me Routes

**Service: `internal/service/userprofile/service.go`**

```go
type Deps struct {
    UserRepo *userrepo.Repo
}

type Service struct { Deps }

func NewService(d Deps) *Service

// GetProfile returns the user's profile by ID within an app.
func (s *Service) GetProfile(ctx context.Context, appID, userID uuid.UUID) (*model.User, error)

// UpdateProfile patches display_name and/or avatar_url.
// Checks display_name uniqueness within the app (excluding self).
func (s *Service) UpdateProfile(ctx context.Context, appID, userID uuid.UUID, displayName, avatarURL *string) (*model.User, error)
```

**Routes (mounted on `/v1/apps/:slug` with Auth middleware):**

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| GET | `/me` | `handleGetMe` | Return authenticated user's profile |
| PATCH | `/me` | `handleUpdateMe` | Update display_name and/or avatar_url |

**PATCH /me request body (all fields optional):**
```json
{
  "display_name": "new name",
  "avatar_url": "https://cdn.example.com/avatar.jpg"
}
```

**PATCH /me response:** Full user object (same as GET /me).

**Error cases:**
- `display_name` taken within app → 409 `DISPLAY_NAME_TAKEN`
- `avatar_url` not validated (IAM stores whatever URL the client provides)

### 2. AdminRole Middleware

**File: `internal/middleware/adminrole.go`**

```go
// AdminRole verifies the authenticated user still has admin role in the DB.
// Must be placed after Auth middleware.
func AdminRole(userRepo *userrepo.Repo) gin.HandlerFunc
```

Logic:
1. Get `claims` from gin context (set by Auth middleware)
2. Get `app` from gin context (set by AppSlugMiddleware)
3. Query `userRepo.FindByID(ctx, app.ID, claims.UserID)`
4. If user not found → 401 `USER_NOT_FOUND`
5. If user disabled → 403 `ACCOUNT_DISABLED`
6. If user role != "admin" → 403 `FORBIDDEN`
7. Store user in context for handler use (avoid double-fetch)

### 3. useradmin Service + /users/* Routes

**Service: `internal/service/useradmin/service.go`**

```go
type Deps struct {
    UserRepo  *userrepo.Repo
    AuditRepo *auditlog.Repo
    OTP       *otp.Service
}

type Service struct { Deps }

func NewService(d Deps) *Service

// ListUsers returns paginated users with optional search keyword.
// Matches against email_lower and display_name (ILIKE).
func (s *Service) ListUsers(ctx context.Context, appID uuid.UUID, query string, cursor string, limit int) (*user.ListPage, error)

// GetUser returns a single user by ID within the app.
func (s *Service) GetUser(ctx context.Context, appID, userID uuid.UUID) (*model.User, error)

// DisableUser sets disabled_at. Rejects if target is the last active admin.
// Writes audit log (best-effort).
func (s *Service) DisableUser(ctx context.Context, appID, actorID, targetID uuid.UUID) error

// EnableUser clears disabled_at. Idempotent. Writes audit log (best-effort).
func (s *Service) EnableUser(ctx context.Context, appID, actorID, targetID uuid.UUID) error

// TriggerPasswordReset sends a password reset OTP to the target user.
// Writes audit log (best-effort).
func (s *Service) TriggerPasswordReset(ctx context.Context, appID, actorID, targetID uuid.UUID) error
```

**Routes (mounted on `/v1/apps/:slug` with Auth + AdminRole middleware + rate limiting):**

| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| GET | `/users` | `handleListUsers` | Paginated user list with search |
| GET | `/users/:id` | `handleGetUser` | Single user detail |
| POST | `/users/:id/disable` | `handleDisableUser` | Disable user account |
| POST | `/users/:id/enable` | `handleEnableUser` | Enable user account |
| POST | `/users/:id/trigger-password-reset` | `handleTriggerPasswordReset` | Send reset OTP |

**Rate limiting:** 100 req/min per admin user (key: `admin:{user_id}`).

**GET /users query parameters:**
- `q` — search keyword (matches email_lower and display_name via ILIKE)
- `cursor` — pagination cursor (opaque string, base64-encoded `(created_at, id)`)
- `limit` — items per page (default 20, max 100)

**GET /users response:**
```json
{
  "items": [/* user objects */],
  "next_cursor": "base64...",
  "total": 42
}
```

**Error cases:**
- Disable last admin → 409 `LAST_ADMIN`
- Target user not found → 404 `USER_NOT_FOUND`
- Target already disabled (disable) / already enabled (enable) → 200 idempotent

### 4. audit_logs Repo

**Repo: `internal/repo/auditlog/repo.go`**

```go
type Entry struct {
    ID        uuid.UUID
    AppID     uuid.UUID
    ActorID   *uuid.UUID
    TargetID  *uuid.UUID
    Action    string
    Metadata  map[string]any
    CreatedAt time.Time
}

func (Entry) TableName() string { return "audit_logs" }

type Repo struct { DB *gorm.DB }

func NewRepo(db *gorm.DB) *Repo

// Record inserts an audit log entry. Returns error but callers should not
// fail their operation on audit write failure (best-effort).
func (r *Repo) Record(ctx context.Context, entry *Entry) error
```

**Audit actions:**
- `user.disabled` — admin disabled a user
- `user.enabled` — admin enabled a user
- `user.password_reset_triggered` — admin triggered password reset for a user

**Metadata examples:**
```json
// user.disabled
{"target_email": "user@example.com"}

// user.password_reset_triggered
{"target_email": "user@example.com"}
```

### 5. Main.go Wiring

Add to `cmd/api/main.go`:
1. Create `auditlog.Repo`
2. Create `userprofile.Service`
3. Create `useradmin.Service`
4. Mount `/me` routes with Auth middleware
5. Mount `/users/*` routes with Auth + AdminRole + RateLimit middleware

## Repo Method Additions

### `internal/repo/user/user.go` additions

```go
// UpdateProfile patches display_name and/or avatar_url for the given user.
func (r *Repo) UpdateProfile(ctx context.Context, appID, id uuid.UUID, displayName, avatarURL *string) error

// CountActiveAdmins returns the number of non-disabled admin users in the app.
func (r *Repo) CountActiveAdmins(ctx context.Context, appID uuid.UUID) (int64, error)

// List returns paginated users with optional search query.
// Cursor is base64-encoded (created_at, id) composite.
func (r *Repo) List(ctx context.Context, filter ListFilter) (*ListPage, error)
```

## Data Flow

```
Self-service:
  Request → AppSlug → Auth → userprofile handler → userprofile service → user repo

Admin:
  Request → AppSlug → Auth → AdminRole (JWT + DB check) → RateLimit → useradmin handler
    → useradmin service → user repo + auditlog repo
```

## Test Coverage

### Repo tests
- `user.UpdateProfile` — happy path, display_name uniqueness conflict
- `user.CountActiveAdmins` — correct count, disabled admins excluded
- `user.List` — pagination, search, empty result
- `auditlog.Record` — happy path

### Service tests
- `userprofile.GetProfile` — happy path, not found
- `userprofile.UpdateProfile` — happy path, display_name taken, partial update (only avatar_url)
- `useradmin.ListUsers` — pagination, search
- `useradmin.DisableUser` — happy path, last admin protection, idempotent
- `useradmin.EnableUser` — happy path, idempotent
- `useradmin.TriggerPasswordReset` — happy path, user not found

### HTTP handler tests
- GET /me — 200 with profile
- PATCH /me — 200 with updated fields, 409 display_name taken
- GET /users — 200 with paginated results, search
- GET /users/:id — 200, 404
- POST /users/:id/disable — 200, 409 last admin, 403 non-admin
- POST /users/:id/enable — 200, 404
- POST /users/:id/trigger-password-reset — 200, 404

## Exit Criteria

- `GET /v1/apps/{slug}/me` returns authenticated user's profile
- `PATCH /v1/apps/{slug}/me` updates display_name and/or avatar_url
- `GET /v1/apps/{slug}/users` returns paginated, searchable user list (admin only)
- `GET /v1/apps/{slug}/users/:id` returns user detail (admin only)
- `POST /v1/apps/{slug}/users/:id/disable` disables user (admin only, last admin protected)
- `POST /v1/apps/{slug}/users/:id/enable` enables user (admin only)
- `POST /v1/apps/{slug}/users/:id/trigger-password-reset` sends reset OTP (admin only)
- Admin role verified against DB (not just JWT)
- Audit logs written for all admin actions
- Rate limiting on admin endpoints
- All tests pass: `make lint`, `make test`
- Tracker updated
