# iam

Reusable **Identity and Access Management (IAM)** service: authentication, sessions, account self-management, and admin user operations.

No billing. No product business logic.

## Scope

| In scope | Out of scope |
|----------|--------------|
| Register, login, refresh, logout | Subscription / billing / payments |
| OTP email verification | Product domains (projects, skills, chat, ...) |
| Password reset | OAuth / SMS provider implementations (Phase 2+ ADRs) |
| `/v1/apps/{slug}/me`, avatar, sessions, login history | |
| Per-app admin + cross-app super-admin | |
| Self-service account deletion | |
| Internal per-app HMAC API + webhooks | |

## Consumers

Multiple independent consumer applications integrate via the public auth API, the internal HMAC API, and outbound webhooks. See [ARCHITECTURE.md](./ARCHITECTURE.md) → "Consumer integration modes" for the contract.

## Quick start

Bootstrap — Wave 1 infrastructure is in place. Runnable auth API lands in Wave 2.

```bash
cp .env.example .env   # fill DATABASE_URL, JWT_SECRET (>=32 bytes) for later waves
make migrate-up        # requires DATABASE_URL
make build             # bin/iam-api, bin/iamctl
./bin/iamctl apps create --slug=demo --display-name="Demo App"
./bin/iam-api          # GET /healthz
make test
```

## Documentation

- [AGENTS.md](./AGENTS.md) — agent / contributor manual
- [ARCHITECTURE.md](./ARCHITECTURE.md) — boundaries and layering
- [docs/adr/](./docs/adr/) — architecture decision records (0001 scope, 0002 multi-app tenancy)
- [docs/migration/implementation-path.md](./docs/migration/implementation-path.md) — incremental implementation waves (start here for coding)
- [docs/migration/extraction-plan.md](./docs/migration/extraction-plan.md) — initial Strangler Fig plan (Superpower plan, operator language)
- [docs/migration/tracker.md](./docs/migration/tracker.md) — execution tracker (update on every state change)

## Module

```
github.com/nathan-tsien/iam
```

Default HTTP port: **8090** (see `.env.example`).
