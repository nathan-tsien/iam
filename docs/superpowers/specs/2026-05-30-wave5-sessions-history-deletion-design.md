---
name: wave5-sessions-history-deletion
overview: Wave 5 design - session management, login history, account self-deletion with PII anonymization
status: approved
---

# Wave 5: Sessions, Login History, Account Deletion Design

## Goal

Self-service session management (list/revoke), login history, and account deletion with soft-delete + PII anonymization.

## Design Decisions

### Sessions = refresh tokens

No separate sessions table. Each row in `iam.refresh_tokens` represents a session. Active sessions are those with `revoked_at IS NULL` AND `expires_at > now()`. The current session is identified by matching the refresh token ID from the JWT claims.

### Current session flagging

The GET /me/sessions response includes an `is_current` boolean on each session. The handler passes the refresh token ID from the JWT claims to the service, which compares it against each session's ID.

### Account deletion: password confirmation

DELETE /me requires the user's current password in the request body. This prevents accidental or malicious deletion if someone gains access to a logged-in session (e.g., shared device). Uses `authpkg.ComparePassword` directly (bcrypt) to avoid importing the full auth service.

### Soft delete + PII anonymization

On account deletion:
- Set `deleted_at` and `disabled_at` to now
- Anonymize email to `deleted-{user_id}@invalid`
- Clear `display_name` and `avatar_url`
- Revoke all refresh tokens (immediate session termination)

Deleted users are filtered out of `FindByID`, `FindByEmail`, and `FindByEmailInsensitive` queries, making them invisible to authentication.

### Login history: cursor pagination

Uses `occurred_at` as cursor (descending). Consistent with the project's cursor-based pagination pattern from Wave 4. Returns `next_cursor` for the next page.

### Webhook: audit log only

The implementation plan says "enqueue webhook" for account deletion, but the webhook outbox infrastructure is Wave 6 (P1-T8). Wave 5 writes an `audit_logs` entry with action `user.deleted` using the existing fire-and-forget goroutine pattern. Wave 6 will add the outbox table and dispatch worker.

### Architecture: new sessions service

Session management gets its own service (`internal/service/sessions/`) rather than extending userprofile. Rationale: sessions and login history are conceptually distinct from profile management, and userprofile would grow from 2 methods to 8+. Account deletion stays in userprofile since it's a self-service profile operation.

## Modules

### 1. Repo Additions

**`internal/repo/refresh/refresh.go` — new methods:**

```go
// ListActive returns non-expired, non-revoked refresh tokens for a user within an app.
func (r *Repo) ListActive(ctx context.Context, userID, appID uuid.UUID) ([]RefreshToken, error)

// Revoke sets revoked_at on a specific token. Ownership check: only revokes
// if the token belongs to the given user. Returns changed=false if not found
// or already revoked.
func (r *Repo) Revoke(ctx context.Context, id, userID uuid.UUID) (changed bool, error)

// RevokeAllForUser revokes all active tokens for a user within an app.
func (r *Repo) RevokeAllForUser(ctx context.Context, userID, appID uuid.UUID) error
```

**`internal/repo/loginevent/repo.go` — new method:**

```go
// ListByUser returns login events for a user within an app, paginated by occurred_at cursor.
// Cursor is the occurred_at timestamp of the last item; pass zero time for the first page.
// Returns events and the cursor for the next page (nil if no more).
func (r *Repo) ListByUser(ctx context.Context, userID, appID uuid.UUID, cursor time.Time, limit int) ([]Event, *time.Time, error)
```

**`internal/repo/user/user.go` — new method + query filter changes:**

```go
// SoftDelete marks a user as deleted and anonymizes PII. Idempotent.
func (r *Repo) SoftDelete(ctx context.Context, appID, id uuid.UUID) error
```

Add `WHERE deleted_at IS NULL` to:
- `FindByID`
- `FindByEmail`
- `FindByEmailInsensitive`

**`internal/model/user.go` — new helper:**

```go
func (u *User) Deleted() bool { return u.DeletedAt != nil }
```

### 2. Sessions Service

**Service: `internal/service/sessions/service.go`**

```go
type Deps struct {
    RefreshRepo    *refresh.Repo
    LoginEventRepo *loginevent.Repo
}

type Service struct { Deps }

func NewService(d Deps) *Service

// ListSessions returns active sessions for a user within an app.
// currentTokenID is used to set is_current on the matching session.
func (s *Service) ListSessions(ctx, userID, appID, currentTokenID uuid.UUID) ([]SessionInfo, error)

// RevokeSession revokes a specific session by ID. Ownership check ensures
// the session belongs to the given user. Returns ErrNotFound if not found.
func (s *Service) RevokeSession(ctx, userID, sessionID uuid.UUID) error

// RevokeAllSessions revokes all sessions for a user within an app.
func (s *Service) RevokeAllSessions(ctx, userID, appID uuid.UUID) error

// LoginHistory returns paginated login events for a user within an app.
func (s *Service) LoginHistory(ctx, userID, appID uuid.UUID, cursor time.Time, limit int) ([]LoginEvent, *time.Time, error)
```

**Types:**

```go
type SessionInfo struct {
    ID          uuid.UUID
    DeviceLabel *string
    UserAgent   *string
    IP          *string
    CreatedAt   time.Time
    LastSeenAt  *time.Time
    IsCurrent   bool
}

type LoginEvent struct {
    ID         uuid.UUID
    Kind       string
    IP         *string
    UserAgent  *string
    OccurredAt time.Time
}
```

**Error sentinels:** `ErrNotFound`

### 3. Userprofile Service Extension

**`internal/service/userprofile/service.go` — add to Deps:**

```go
type Deps struct {
    UserRepo    *userrepo.Repo
    RefreshRepo *refresh.Repo       // NEW
    AuditRepo   *auditlog.Repo      // NEW
}
```

**New method:**

```go
// DeleteAccount soft-deletes the user, anonymizes PII, and revokes all sessions.
// Verifies password before proceeding. Returns ErrInvalidPassword on mismatch.
func (s *Service) DeleteAccount(ctx, appID, userID uuid.UUID, password string) error
```

Logic:
1. Load user via `UserRepo.FindByID(ctx, appID, userID)`
2. Verify password via `authpkg.ComparePassword(user.PasswordHash, password)`
3. Call `UserRepo.SoftDelete(ctx, appID, userID)`
4. Call `RefreshRepo.RevokeAllForUser(ctx, userID, appID)`
5. Write audit log entry (action=`user.deleted`, fire-and-forget goroutine)

**Error sentinels:** `ErrInvalidPassword`

### 4. OpenAPI Spec Additions

**New paths in `api/openapi.yaml`:**

| Method | Path | Operation ID | Description |
|--------|------|-------------|-------------|
| GET | `/me/sessions` | `getMeSessions` | List active sessions |
| DELETE | `/me/sessions/{id}` | `deleteMeSession` | Revoke a specific session |
| DELETE | `/me/sessions` | `deleteMeSessions` | Revoke all sessions |
| GET | `/me/login-history` | `getMeLoginHistory` | Paginated login history |
| DELETE | `/me` | `deleteMe` | Delete own account |

**New schemas:**

```yaml
Session:
  type: object
  properties:
    id: { type: string, format: uuid }
    device_label: { type: string, nullable: true }
    user_agent: { type: string, nullable: true }
    ip: { type: string, nullable: true }
    created_at: { type: string, format: date-time }
    last_seen_at: { type: string, format: date-time, nullable: true }
    is_current: { type: boolean }
  required: [id, created_at, is_current]

SessionsResponse:
  type: object
  properties:
    sessions:
      type: array
      items: { $ref: '#/components/schemas/Session' }
  required: [sessions]

LoginEventSchema:
  type: object
  properties:
    id: { type: string, format: uuid }
    kind: { type: string }
    ip: { type: string, nullable: true }
    user_agent: { type: string, nullable: true }
    occurred_at: { type: string, format: date-time }
  required: [id, kind, occurred_at]

LoginHistoryResponse:
  type: object
  properties:
    events:
      type: array
      items: { $ref: '#/components/schemas/LoginEventSchema' }
    next_cursor: { type: string, nullable: true }
  required: [events]

DeleteMeRequest:
  type: object
  properties:
    password: { type: string, minLength: 1 }
  required: [password]
```

**Response codes:**
- GET /me/sessions: 200 (SessionsResponse), 401, 500
- DELETE /me/sessions/{id}: 204, 401, 404, 500
- DELETE /me/sessions: 204, 401, 500
- GET /me/login-history: 200 (LoginHistoryResponse), 401, 500
- DELETE /me: 204, 401 (wrong password), 500

### 5. HTTP Handler Additions

**`internal/httpapi/strict.go`:**

Add `SessionsSvc *sessions.Service` to `StrictServer`.

Add all five new operations to `authRequiredOps` map.

Handler implementations:
- `GetMeSessions` — extract user ID + refresh token ID from JWT claims, call `SessionsSvc.ListSessions`
- `DeleteMeSession` — parse session ID from path, call `SessionsSvc.RevokeSession`, map ErrNotFound → 404
- `DeleteMeSessions` — call `SessionsSvc.RevokeAllSessions`
- `GetMeLoginHistory` — parse `cursor` (time) and `limit` (int, default 20, max 100) query params, call `SessionsSvc.LoginHistory`
- `DeleteMe` — parse password from body, call `ProfileSvc.DeleteAccount`, map ErrInvalidPassword → 401

**Rate limiting:** Add `deleteMe` to `rateLimitOps` at 5 req/min (prevents brute-force password guessing).

### 6. Main.go Wiring

Add to `cmd/api/main.go`:
1. Create `sessions.Service` with `refreshRepo` and `loginEventRepo`
2. Add `RefreshRepo` and `AuditRepo` to `userprofile.Deps`
3. Pass `SessionsSvc` to `StrictServer`

## Data Flow

```
Session management:
  Request → AppSlug → Auth → sessions handler → sessions service → refresh repo / loginevent repo

Account deletion:
  Request → AppSlug → Auth → userprofile handler → userprofile service
    → user repo (soft delete) + refresh repo (revoke all) + auditlog repo (best-effort)
```

## Test Coverage

### Repo tests

- `refresh.ListActive` — returns only active tokens, excludes revoked/expired
- `refresh.Revoke` — happy path, idempotent (already revoked), ownership check (wrong user)
- `refresh.RevokeAllForUser` — revokes all tokens for user in app
- `loginevent.ListByUser` — returns events in descending order, cursor pagination works
- `user.SoftDelete` — sets deleted_at, anonymizes email, clears display_name/avatar_url, idempotent
- `user.FindByID` — excludes soft-deleted users
- `user.FindByEmail` — excludes soft-deleted users

### Service tests

- `sessions.ListSessions` — returns active sessions, flags current session correctly
- `sessions.RevokeSession` — happy path, not found, wrong user
- `sessions.RevokeAllSessions` — revokes everything
- `sessions.LoginHistory` — pagination, empty result
- `userprofile.DeleteAccount` — happy path (verifies deletion + revocation), wrong password

### HTTP handler tests

- GET /me/sessions — 200 with session list
- DELETE /me/sessions/{id} — 204, 404
- DELETE /me/sessions — 204
- GET /me/login-history — 200 with events, pagination
- DELETE /me — 204 with correct password, 401 with wrong password
- Deleted user cannot authenticate (integration test)

## Exit Criteria

- `GET /v1/apps/{slug}/me/sessions` returns active sessions with `is_current` flag
- `DELETE /v1/apps/{slug}/me/sessions/{id}` revokes a specific session
- `DELETE /v1/apps/{slug}/me/sessions` revokes all sessions
- `GET /v1/apps/{slug}/me/login-history` returns paginated login events
- `DELETE /v1/apps/{slug}/me` soft-deletes account with password confirmation
- Deleted users cannot log in (filtered from auth queries)
- Email anonymized to `deleted-{user_id}@invalid`
- All refresh tokens revoked on account deletion
- Audit log entry written for account deletion
- All tests pass: `make lint`, `make test`
- Tracker updated
