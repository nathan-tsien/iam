# ADR-0002: Multi-app tenancy and identity model

## Status

Accepted

Supersedes [ADR-0001](./0001-iam-service-scope.md) § "Out of scope" for **tenancy** only. ADR-0001 remains authoritative for billing exclusion, consumer-side `users_local` ownership, and the core auth / me / admin surface.

## Context

This IAM service serves multiple independent consumer applications within one startup portfolio. Each product may onboard users independently; the same email address may register separately in different products without sharing an account.

Design sessions established the following requirements:

| Requirement | Decision |
|-------------|----------|
| Multi-product isolation | Per-app user pools (model B) |
| Phone registration / SMS OTP | Schema reserved in Phase 1; flows deferred to Phase 2+ |
| Third-party login (OAuth / OIDC / regional providers) | Schema reserved in Phase 1; adapters deferred to Phase 2+ |
| Target regions | China and global (dual-stack providers in later ADRs) |
| Session management | List and revoke active sessions |
| Login history | User-visible login event log |
| Account deletion | Self-service delete with soft delete and PII anonymization |
| Cross-app administration | Global super-admin role |
| App onboarding | `iamctl` CLI (separate binary) |

ADR-0001 assumed a single implicit user pool and deferred tenancy. That is insufficient for the portfolio model above.

## Decision

### 1. Tenancy model: per-app user pools (model B)

- Every user row belongs to exactly one app via `users.app_id`.
- Uniqueness is scoped per app: `UNIQUE (app_id, email)` in Phase 1.
- The same email may exist in multiple apps as distinct user records.
- JWT access tokens include an `aud` claim equal to the app's configured audience. Consumers **must** reject tokens whose `aud` does not match their app.

### 2. Apps registry

New table `iam.apps`:

| Column | Purpose |
|--------|---------|
| `id` | UUID primary key |
| `slug` | Stable identifier used in URL paths (e.g. `my-product`) |
| `display_name` | Human-readable label |
| `jwt_audience` | Value written into JWT `aud` |
| `hmac_secret_hash` | Per-app secret for internal HMAC API calls |
| `mail_from_name` | Outbound mail display name for this app |
| `oauth_redirect_allowlist` | JSON allowlist for future OAuth callbacks |
| `webhook_url` | Outbound webhook target for this app |
| `disabled_at` | Soft-disable an app without deleting data |
| timestamps | `created_at`, `updated_at` |

App provisioning is **not** exposed on the public HTTP API in Phase 1. Operators use the `iamctl` CLI (see §8).

### 3. Identity model: dual-track in Phase 1

**Phase 1 (implemented):**

- Email remains on `users.email` (primary login identifier).
- Table `iam.user_identities` is created in the baseline migration but **not written to** in Phase 1.

**Phase 2+ (phone and OAuth):**

- Phone and OAuth identities are stored in `user_identities` with `kind` values such as `phone`, `oauth_google`, `oauth_apple`, `oauth_github`, `oauth_wechat`, `oauth_alipay`.
- Backfill existing email rows into `user_identities`.
- After backfill, `users.email` becomes a read-only denormalized field; all identity writes go through `user_identities`.

`user_identities` schema (created in Phase 1, populated from Phase 2):

| Column | Purpose |
|--------|---------|
| `id` | UUID primary key |
| `user_id` | FK → `users.id` |
| `app_id` | FK → `apps.id` (denormalized for uniqueness) |
| `kind` | Identity type (see above) |
| `value` | Email, E.164 phone, or OAuth subject |
| `verified_at` | Verification timestamp |
| `is_primary` | Primary identity flag |
| timestamps | `created_at` |

Constraint: `UNIQUE (app_id, kind, value)`.

`users.password_hash` is nullable to support future OAuth-only accounts.

### 4. API path convention: app slug in URL

All public and app-scoped routes include the app slug:

```
POST   /v1/apps/{slug}/auth/register
POST   /v1/apps/{slug}/auth/login
GET    /v1/apps/{slug}/me
GET    /v1/apps/{slug}/me/sessions
DELETE /v1/apps/{slug}/me/sessions/{session_id}
GET    /v1/apps/{slug}/me/login-history
DELETE /v1/apps/{slug}/me
GET    /v1/apps/{slug}/users          (app admin)
```

Internal HMAC routes are also app-scoped:

```
GET  /v1/internal/apps/{slug}/users/{id}
POST /v1/internal/apps/{slug}/users:batchLookup
POST /v1/internal/apps/{slug}/users:exists
```

Middleware resolves `{slug}` → `apps.id`, rejects disabled apps, and injects app context for handlers.

### 5. Super-admin: system app + grants table

Cross-app administration uses a dedicated system app rather than a separate login stack:

- Baseline migration seeds app `slug = '_iam'` (system app).
- Super-admin operators are normal users under the `_iam` app.
- Table `iam.super_admins` records which `_iam` users may perform cross-app operations:

| Column | Purpose |
|--------|---------|
| `user_id` | FK → `users.id` (must belong to `_iam` app) |
| `granted_at` | Grant timestamp |
| `granted_by` | FK → `users.id` (who granted) |

Super-admin routes (require `_iam` JWT + `super_admins` membership):

```
GET  /v1/admin/users              (optional ?app_id= filter)
GET  /v1/admin/apps
POST /v1/admin/apps/{slug}/users/{id}/disable
```

Per-app admin routes remain under `/v1/apps/{slug}/users/*` and are limited to users with an admin role **within that app**.

### 6. Session management

Extend `refresh_tokens` with session metadata:

| Column | Purpose |
|--------|---------|
| `app_id` | Denormalized app scope |
| `device_label` | User-visible session name |
| `user_agent` | Client user agent |
| `ip` | Client IP at issue time |
| `last_seen_at` | Updated on refresh |

Endpoints:

- `GET /v1/apps/{slug}/me/sessions` — list active sessions for the authenticated user.
- `DELETE /v1/apps/{slug}/me/sessions/{id}` — revoke one session.
- `DELETE /v1/apps/{slug}/me/sessions` — revoke all sessions except the current one (optional query flag to include current).

### 7. Login history

New table `iam.login_events`:

| Column | Purpose |
|--------|---------|
| `id` | UUID primary key |
| `user_id` | FK → `users.id` |
| `app_id` | FK → `apps.id` |
| `kind` | `login_success`, `login_failure`, `logout`, `refresh`, `password_reset` |
| `ip` | Client IP |
| `user_agent` | Client user agent |
| `occurred_at` | Event timestamp |

Writes are **best-effort and non-blocking**: a failed insert must not fail the login response.

Endpoint: `GET /v1/apps/{slug}/me/login-history` (paginated, newest first).

### 8. Self-service account deletion

`DELETE /v1/apps/{slug}/me`:

1. Set `users.disabled_at` and `users.deleted_at`.
2. Anonymize PII: replace email with `deleted-{user_id}@invalid`, clear `display_name` and avatar references.
3. Revoke all refresh tokens for the user.
4. Enqueue `user.deleted` webhook event (per-app outbox routing).

Hard delete is out of scope for Phase 1. Consumer applications retain `users_local` rows keyed by `user_id`; anonymization preserves referential integrity for audit trails.

### 9. Per-app HMAC secrets and webhooks

- Replace the global `INTERNAL_HMAC_SECRET` environment variable with per-app secrets stored in `apps.hmac_secret_hash`.
- Internal API callers authenticate with the secret belonging to the target app.
- Webhook outbox rows include `app_id`; delivery uses `apps.webhook_url` and the app's HMAC secret for signing.
- Events scoped to an app are delivered only to that app's webhook endpoint.

### 10. `iamctl` CLI

Separate binary at `cmd/iamctl/main.go` (not embedded in the API server):

| Command | Purpose |
|---------|---------|
| `iamctl apps create --slug=... --display-name=...` | Register a new app; prints HMAC secret once |
| `iamctl apps list` | List registered apps |
| `iamctl apps disable --slug=...` | Soft-disable an app |
| `iamctl super-admins grant --user-id=...` | Grant cross-app admin (Phase 1 minimal surface) |

The CLI connects via `DATABASE_URL` (same as the API server). Secret generation uses cryptographically secure random bytes; only the hash is persisted.

### 11. Phase 1 scope boundary

**In Phase 1 (this repository):**

- Per-app user pools, apps table, URL path convention, JWT `aud`.
- Email + password + OTP flows (lifted from source codebase).
- `/me`, avatar, app-scoped admin, internal HMAC API, webhook outbox.
- Sessions list/revoke, login history, self-delete.
- `user_identities` table created but unused.
- `iamctl` for app provisioning.

**Deferred to Phase 2+ ADRs (not Phase 1 code):**

- SMS provider adapters (China + global dual stack).
- OAuth / OIDC provider adapters.
- `user_identities` backfill and dual-write period.
- JWKS / RS256 token signing (see future topology ADR).

## Consequences

### Positive

- Strict isolation between products: token leakage in one app cannot authenticate in another when consumers validate `aud`.
- Per-app HMAC limits blast radius of secret compromise.
- Schema is ready for phone and OAuth without another breaking migration.
- Super-admin reuses the standard auth stack instead of a parallel login system.

### Negative

- Every public route gains an `{slug}` segment; OpenAPI, SDKs, and frontend base URLs must be updated at cutover.
- Operators must run `iamctl` (or future admin API) before a new product can authenticate users.
- Two admin layers (per-app admin vs super-admin) require clear RBAC documentation and tests.

### Unchanged from ADR-0001

- No billing, subscriptions, or product business logic in this repository.
- Consumer-side `users_local` cache remains owned by each consumer application.
- Phase 1 continues shared `JWT_SECRET` with local verify at consumers (with mandatory `aud` check); JWKS migration is a separate future ADR.
- IAM-owned `audit_logs` for admin actions (scheme A).

## Related

- [ADR-0001: IAM service scope](./0001-iam-service-scope.md) — superseded for tenancy only
- Planned ADR-0003: DB topology (shared Postgres, `iam` schema, audit scheme A)
- Planned ADR-0004: SMS provider abstraction
- Planned ADR-0005: OAuth provider abstraction
- [ARCHITECTURE.md](../../ARCHITECTURE.md)
- [docs/migration/tracker.md](../migration/tracker.md)
