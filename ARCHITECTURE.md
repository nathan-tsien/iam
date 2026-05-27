# iam Architecture

Narrative layering for the reusable IAM HTTP service and its relationship to product consumers.

Companion docs:

- **`AGENTS.md`** — agent manual and scope guardrails
- **`docs/adr/0001-iam-service-scope.md`** — in/out of scope decision
- **`docs/adr/0002-multi-app-and-identity-model.md`** — per-app tenancy, identity schema, sessions, admin layers
- **`docs/migration/implementation-path.md`** — incremental waves and ADR-on-demand gates
- **`docs/migration/extraction-plan.md`** — initial Strangler Fig plan (Superpower; operator language)
- **`docs/migration/tracker.md`** — execution progress

## Positioning

```
+-------------------------------------------------------------+
| Consumer applications (multiple, independent deployments)   |
| Business logic, product DB, local user cache (users_local)   |
+--------------------------+----------------------------------+
                           | HTTPS: auth API, internal API,
                           | webhooks, shared JWT verify
+--------------------------v----------------------------------+
| iam (this repository)                                       |
| Register · login · sessions · /me · admin users · webhooks  |
+--------------------------+----------------------------------+
                           | Postgres (iam schema) + Redis
+--------------------------v----------------------------------+
| Mail (SMTP) · object storage (avatars)                      |
+-------------------------------------------------------------+
```

Phase **bootstrap**: repository skeleton and migration tracker only. Runnable API arrives in Phase 1.

## Multi-app tenancy (ADR-0002)

Each consumer application registers as an **app** with a unique `slug`. Users belong to one app; the same email may register separately in different apps.

- Public routes: `/v1/apps/{slug}/auth/*`, `/v1/apps/{slug}/me/*`, `/v1/apps/{slug}/users/*`
- JWT `aud` claim matches the app's audience; consumers must reject mismatched tokens.
- Internal HMAC routes: `/v1/internal/apps/{slug}/users/*` with per-app secrets.
- Super-admin operators authenticate via system app `_iam` and routes under `/v1/admin/*`.
- App provisioning: `iamctl` CLI (`cmd/iamctl`), not the public HTTP API.

## Repository layers

### `cmd/api`

- Process entry: config load, DB/Redis/mail/storage wiring, HTTP server.
- No domain rules — composition root only.

### `cmd/iamctl`

- Operator CLI: create/list/disable apps, grant super-admin.
- Connects via `DATABASE_URL`; separate binary from the API server.

### `internal/auth`

- JWT sign/verify (HS256 initially; JWKS evolution via future ADR).
- Password hash/verify (bcrypt).
- Password policy validation.
- **No** database or HTTP imports.

### `internal/repo`

- GORM repositories: `apps`, `users`, `user_identities`, `refresh_tokens`, `otp_codes`, `login_events`, `audit_logs`, `super_admins`, webhook outbox.
- Migrations live under `migrations/`.

### `internal/service`

- `auth`, `otp`, `userprofile`, `useradmin` orchestration.
- Mail dispatch for OTP flows.
- Webhook outbox (Phase 1 internal API slice).

### `internal/httpapi`

- Gin + oapi-codegen strict handlers for public and internal routes.
- Rate limiting, middleware, error envelope mapping.

### `api/`

- OpenAPI 3.1 contract; codegen config alongside `openapi.yaml`.

## Consumer integration modes

| Mode | Purpose | Phase |
|------|---------|-------|
| **Public auth API** | Browser/app calls `/v1/apps/{slug}/auth/*`, `/v1/apps/{slug}/me/*` | 1 |
| **JWT verify (local)** | Consumer verifies access token with shared `JWT_SECRET` and checks `aud` | 1 |
| **Internal HMAC API** | Per-app `GET /v1/internal/apps/{slug}/users/:id`, batch lookup, exists | 1 |
| **Webhooks** | `user.created` / `user.updated` / disabled / enabled / deleted | 1 |
| **JWKS verify** | Consumer fetches public keys; no shared secret | Future ADR |

Downstream products maintain a **`users_local`** cache table fed by webhooks — they do not join IAM tables directly.

## Data model (target)

IAM schema tables:

- `apps` — registered consumer applications, per-app secrets and webhook targets
- `users` — credentials and profile per app (`app_id` required); email in Phase 1
- `user_identities` — unified identity store (created Phase 1; populated from Phase 2 for phone/OAuth)
- `refresh_tokens` — hashed, rotatable, replay detection, session metadata
- `otp_codes` — hashed, purpose-scoped, app-scoped
- `login_events` — user-visible login history (non-blocking writes)
- `audit_logs` — admin IAM actions (scheme A: owned by IAM)
- `super_admins` — cross-app admin grants for `_iam` app users

Explicitly **not** in IAM schema: product tiers, agent memory flags, project membership.

## Provider evolution

Current path: **LocalProvider** (email + password + SMTP OTP).

Future adapters (separate ADRs each):

- `ClerkProvider` (global)
- `AuthingProvider` / `WechatOAuthProvider` (China)
- `SelfHostedProvider` extensions without forking core services

## Deployment

- Single Go API binary (`cmd/api`), default port **8090**.
- Separate operator CLI (`cmd/iamctl`) for app provisioning.
- Phase 1 dev: shared Postgres instance, separate **`iam` schema** from consumer `public` schema.
- Redis for rate limits and optional webhook outbox retries.

## Related platform plan

This repository implements the **identity-gateway** slice described in the shared platform plan. Profile is colocated here (not a separate profile-service). Billing remains a separate future repository/service.
