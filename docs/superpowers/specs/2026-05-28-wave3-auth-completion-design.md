---
name: wave3-auth-completion
overview: Wave 3 design - password forgot/reset, SMTP mail, rate limiting, login events
status: approved
---

# Wave 3: Auth Completion Design

## Goal

Full public auth surface: password forgot/reset, SMTP mail provider, rate limiting, and login events recording.

## Modules

### 1. Password Forgot/Reset

**Endpoints:**
- `POST /v1/apps/{slug}/auth/password/forgot` - Send reset OTP
- `POST /v1/apps/{slug}/auth/password/reset` - Verify OTP and reset password

**Flow:**
- `ForgotPassword`: Look up user by email (don't leak existence), issue OTP via `mail.PurposePasswordReset`, return 200 always
- `ResetPassword`: Verify OTP, update password, revoke all refresh tokens, return 200

**Service methods:**
- `ForgotPassword(ctx, appID, email) error`
- `ResetPassword(ctx, appID, email, code, newPassword) error`

### 2. SMTP Mail Provider

**Implementation:** Reference family-office-platform SMTP implementation.

**Files:**
- `internal/provider/mail/smtp.go` - SMTPMailer implementing Mailer interface

**Config:**
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDR`, `SMTP_FROM_NAME`

**Mailer selection in main.go:**
- `APP_ENV=development` → LogMailer
- `APP_ENV=production` → SMTPMailer

### 3. Rate Limiting

**Files:**
- `internal/ratelimit/limiter.go` - Interface
- `internal/ratelimit/redis.go` - Redis sliding window
- `internal/ratelimit/memory.go` - In-memory fallback

**Interface:**
```go
type Limiter interface {
    Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}
```

**Redis implementation:** Sorted Set sliding window counter
**Memory implementation:** sync.Map with time-window cleanup

**Rate limits:**
| Endpoint | Limit | Key |
|----------|-------|-----|
| `/auth/login` | 5/min | `{app_id}:{email}:login` |
| `/auth/register` | 3/min | `{app_id}:{ip}:register` |
| `/auth/password/forgot` | 3/min | `{app_id}:{email}:forgot` |

**Fallback:** Redis unavailable → memory limiter + log warning

### 4. Login Events

**Model:** `iam.login_events` table (already in baseline migration)

**Event kinds:** `login_success`, `login_failure`, `logout`, `refresh`, `password_reset`

**Write strategy:** Best-effort goroutine (don't block HTTP response):
```go
go func() {
    _ = loginEventRepo.Record(ctx, appID, userID, kind, ip, ua)
}()
```

**Integration points:**
- Login success → `login_success`
- Login password wrong → `login_failure`
- Logout → `logout`
- Refresh → `refresh`
- ResetPassword → `password_reset`

## Exit Criteria

- `POST /v1/apps/{slug}/auth/password/forgot` sends OTP email
- `POST /v1/apps/{slug}/auth/password/reset` resets password and revokes tokens
- Rate limits enforced on login/register/forgot endpoints
- Login events recorded in `iam.login_events` table
- All auth endpoints covered by tests
