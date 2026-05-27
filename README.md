# iam

Reusable **Identity and Access Management (IAM)** service: authentication, sessions, account self-management, and admin user operations.

No billing. No product business logic.

## Scope

| In scope | Out of scope |
|----------|--------------|
| Register, login, refresh, logout | Subscription / billing / payments |
| OTP email verification | Product domains (projects, skills, chat, ...) |
| Password reset | OAuth provider implementations (future ADR) |
| `/me`, `/me/avatar` | Tenancy / multi-region routing (future ADR) |
| Admin user list / search / disable / enable | |
| Internal HMAC API + webhooks for downstream apps | |

## Consumers

- [family-office-platform](https://github.com/nathan-tsien/family-office-platform) (first extraction source)
- [ash](https://github.com/nathan-tsien/ash) and future product shells (planned)

## Quick start

Bootstrap only — runnable API lands in Phase 1 of the extraction plan.

```bash
cp .env.example .env   # fill JWT_SECRET (>=32 bytes), DATABASE_URL, REDIS_URL
make build
make test
make migrate-up        # no-op until migrations/ is populated
```

## Documentation

- [AGENTS.md](./AGENTS.md) — agent / contributor manual
- [ARCHITECTURE.md](./ARCHITECTURE.md) — boundaries and layering
- [docs/adr/](./docs/adr/) — architecture decision records
- [docs/migration/extraction-plan.md](./docs/migration/extraction-plan.md) — extraction design (from family-office)
- [docs/migration/tracker.md](./docs/migration/tracker.md) — execution tracker (update on every state change)

## Module

```
github.com/nathan-tsien/iam
```

Default HTTP port: **8090** (see `.env.example`).
