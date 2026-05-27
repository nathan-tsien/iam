---
name: wave2-auth-vertical-slice
overview: Wave 2 design - lift auth modules from source repo, implement hybrid routing, JWT aud+sub claims, app_id scoping
status: approved
---

# Wave 2: Auth Vertical Slice Design

## Goal

One app runs **register -> OTP verify -> login -> refresh**; JWT includes correct `aud`; cross-app isolation enforced.

## Key Decisions

### 1. Module Lifting Strategy

**Full lift** from `family-office-platform/backend/internal/` in one pass. Change import path, remove business fields, add `app_id` scoping.

Source modules to lift:
- `internal/auth/jwt.go`, `password.go`, `passwordpolicy/`
- `internal/repo/user/` (model + repo)
- `internal/repo/refresh/` (model + repo)
- `internal/service/auth/auth.go`, `password_reset.go`
- `internal/service/otp/otp.go`
- `internal/middleware/auth.go`

### 2. Routing: Hybrid Mode

**Unauthenticated routes** (no JWT yet): URL path identifies app.

```
POST /v1/apps/{slug}/auth/register
POST /v1/apps/{slug}/auth/check-availability
POST /v1/apps/{slug}/auth/otp/verify
POST /v1/apps/{slug}/auth/login
POST /v1/apps/{slug}/auth/refresh
POST /v1/apps/{slug}/auth/logout
POST /v1/apps/{slug}/auth/password/forgot
POST /v1/apps/{slug}/auth/password/reset
```

**Authenticated routes** (Wave 4+): Extract app from JWT `aud` claim, cross-validate against path if present.

### 3. JWT Claims: aud + sub

```json
{
  "sub": "user-uuid",
  "aud": "demo",
  "role": "user",
  "exp": 1717000000
}
```

- `aud` = app.slug, taken from app.Model in context at login time
- Bearer middleware verifies JWT, checks `aud` matches current request's app slug

### 4. Data Model Changes

**User model** (`repo/user/model.go`):
- Remove: `Tier`, `AgentMemoryPaused` fields
- Add: `AppID uuid.UUID` (not null, indexed)
- All repo methods add `appID uuid.UUID` parameter

**RefreshToken model** (`repo/refresh/model.go`):
- Add: `AppID uuid.UUID` (not null, indexed)
- Rotate/Revoke scoped by `(app_id, user_id)`

**OTP** (service layer, not GORM):
- Key format: `{app_id}:{email}:{purpose}`

### 5. Middleware

**AppSlugMiddleware**:
- Parse `{slug}` from URL path
- Query `apps` table (optional LRU cache)
- Check `disabled_at` -> 403 if disabled
- Inject `app.Model` into `gin.Context`

**BearerMiddleware** (for authenticated routes in Wave 4+):
- Verify JWT signature
- Check `aud` matches request's app slug
- Inject user claims into context

### 6. Package Structure

```
internal/
├── auth/
│   ├── jwt.go
│   ├── password.go
│   └── passwordpolicy/
├── repo/
│   ├── user/
│   │   ├── model.go
│   │   └── repo.go
│   └── refresh/
│       ├── model.go
│       └── repo.go
├── service/
│   ├── auth/
│   │   └── auth.go
│   └── otp/
│       └── otp.go
├── middleware/
│   ├── app.go
│   └── auth.go
└── httpapi/
    ├── auth.go
    └── auth_test.go
```

### 7. Testing

All tests use **real Postgres** via `TEST_DATABASE_URL` env var.

| Package | Coverage |
|---------|----------|
| `auth` | JWT Sign/Verify, expiry, wrong secret; Password Hash/Verify; policy rules |
| `repo/user` | CRUD, cross-app isolation (same email, different app = different user) |
| `repo/refresh` | Create/Rotate, Revoke invalidates old token, cross-app isolation |
| `service/auth` | Register success, duplicate error, Login success, wrong password, cross-app same email |
| `service/otp` | Issue/Verify success, expired/wrong code failure |
| `middleware` | AppSlugMiddleware parse/disabled app; BearerMiddleware pass/aud mismatch |

Run with `go test -p 1 ./...` to avoid parallel contention on shared test DB.

## PR Structure

| PR | Content | Verification |
|----|---------|--------------|
| PR-1 | `internal/auth` + `repo/user` + `repo/refresh` (lift + app_id) | `make test` |
| PR-2 | `service/auth` + `service/otp` + `middleware/` | `make test` |
| PR-3 | `httpapi/auth.go` + `cmd/api/main.go` wiring | `curl` e2e |

## Exit Criteria

- `make lint` + `make test` green
- app `demo`: register -> login -> refresh end-to-end via curl
- Token for `demo` rejected when used against another app slug (aud check)
