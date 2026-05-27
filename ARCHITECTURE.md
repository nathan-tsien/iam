# iam Architecture

Narrative layering for the reusable IAM HTTP service and its relationship to product consumers.

Companion docs:

- **`AGENTS.md`** — agent manual and scope guardrails
- **`docs/adr/0001-iam-service-scope.md`** — in/out of scope decision
- **`docs/migration/extraction-plan.md`** — Strangler Fig extraction from family-office
- **`docs/migration/tracker.md`** — execution progress

## Positioning

```
+-------------------------------------------------------------+
| Product shells (family-office, ash, future MVPs)            |
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

Phase **bootstrap**: repository skeleton and migration tracker only. Runnable API arrives in extraction Phase 1.

## Repository layers

### `cmd/api`

- Process entry: config load, DB/Redis/mail/storage wiring, HTTP server.
- No domain rules — composition root only.

### `internal/auth`

- JWT sign/verify (HS256 initially; JWKS evolution via future ADR).
- Password hash/verify (bcrypt).
- Password policy validation.
- **No** database or HTTP imports.

### `internal/repo`

- GORM repositories: `users`, `refresh_tokens`, `otp_codes`, `audit_logs` (admin actions).
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
| **Public auth API** | Browser/app calls `/v1/auth/*`, `/v1/me` | 1 |
| **JWT verify (local)** | Consumer verifies access token with shared `JWT_SECRET` | 1 |
| **Internal HMAC API** | `GET /v1/internal/users/:id`, batch lookup, exists | 1 |
| **Webhooks** | `user.created` / `user.updated` / disabled / enabled | 2 |
| **JWKS verify** | Consumer fetches public keys; no shared secret | Future ADR |

Downstream products maintain a **`users_local`** cache table fed by webhooks — they do not join IAM tables directly.

## Data model (target)

IAM schema tables (names negotiable via ADR):

- `users` — credentials, role, profile fields, verification/disabled timestamps
- `refresh_tokens` — hashed, rotatable, replay detection
- `otp_codes` — hashed, purpose-scoped
- `audit_logs` — admin IAM actions (scheme A: owned by IAM, not consumer)

Explicitly **not** in IAM schema: product tiers, agent memory flags, project membership.

## Provider evolution

Current path: **LocalProvider** (email + password + SMTP OTP) — code copied from family-office.

Future adapters (separate ADRs each):

- `ClerkProvider` (global)
- `AuthingProvider` / `WechatOAuthProvider` (China)
- `SelfHostedProvider` extensions without forking core services

## Deployment

- Single Go binary, default port **8090**.
- Phase 1 dev: shared Postgres instance, separate **`iam` schema** from consumer `public` schema.
- Redis for rate limits and optional webhook outbox retries.

## Related platform plan

This repository implements the **identity-gateway** slice described in the shared platform plan. Profile is colocated here (not a separate profile-service). Billing remains a separate future repository/service.
