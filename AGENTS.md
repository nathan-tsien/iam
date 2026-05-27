# AGENTS.md

Operating manual for AI coding agents working on the **iam** repository.

## What this project is

**iam** is a reusable **Identity and Access Management** HTTP service:

- Authentication (register, login, refresh, logout, OTP, password reset)
- Account self-service (`/me`, avatar upload)
- Admin user management (list, search, disable, enable, trigger password reset)
- Internal HMAC-protected APIs and webhooks for downstream products

It is **not** a billing service, subscription engine, or host for product-specific business logic.

Extraction source: `family-office-platform/backend`. Progress: **`docs/migration/tracker.md`**.

## Documentation conventions

- **`AGENTS.md` / `CLAUDE.md` / `README.md` / `ARCHITECTURE.md`**: English.
- **`docs/adr/`**: English (Status, Context, Decision, Consequences).
- **Code comments and logs**: English only.
- **User-facing API strings**: English (product UIs localize at the consumer layer).

Use ASCII `-` for bullets and `1.` for ordered lists in prose docs.

## Inviolable scope guardrails

Stop and ask before crossing these lines:

1. **No billing or subscriptions** in this repository.
2. **No product business logic** (projects, skills, agent chat, approvals, notifications, etc.).
3. **No consumer imports** — do not depend on `family-office-platform`, `ash`, or `cogito` Go/TS modules.
4. **No business fields on `User`** — fields like `agent_memory_paused` belong in consumer apps, not IAM.
5. **Provider adapters are additive** — Clerk / Wechat / Authing come via new ADRs, not ad-hoc routes.

## Package layering

| Path | Holds | Forbidden |
|------|-------|-----------|
| `internal/auth` | JWT, password hashing, password policy | DB, HTTP, mail |
| `internal/repo/*` | GORM persistence | HTTP handlers |
| `internal/service/*` | Business orchestration | Gin imports |
| `internal/httpapi/*` | HTTP adapters, OpenAPI handlers | Direct SQL |
| `cmd/api` | Wiring, config, server boot | Domain logic |

Dependency direction: **`httpapi` → `service` → `repo` → `auth`**. Reverse edges forbidden.

## Coding standards

- Go **1.25+**, `gofmt`, `go vet` baseline.
- Prefer explicit errors; wrap with `%w` for inspection upstream.
- Never log secrets, OTP plaintext (except dev-aid paths gated by config), or bearer tokens.
- Database migrations: additive-first; document breaking changes in ADRs.
- OpenAPI is the contract source for public HTTP surfaces once `api/openapi.yaml` lands.

## Testing posture

- Every new `repo` and `service` package ships with `_test.go` coverage for happy path + primary failure modes.
- DB-backed tests: run with **`go test -p 1 ./...`** when sharing one test database (same discipline as family-office backend).
- Do not `t.Skip` to unblock CI without an ADR note or maintainer approval.

## Commands

```bash
make build
make lint
make test
make migrate-up
```

## What to do when you finish a task

1. `make lint` and `make test` succeed for impacted packages.
2. Update **`docs/migration/tracker.md`** (status, dates, commit ref).
3. Update **`docs/adr/`** if architecture intent changed (supersede, do not rewrite accepted ADRs).
4. Keep **`docs/migration/extraction-plan.md`** aligned with observable behavior when the plan itself changes.

## When uncertain

Valid moves:

- Ask the maintainer.
- Add `// TODO(iam): ...` with English rationale.
- Draft a new ADR before irreversible schema or API changes.

Never valid moves:

- Merging IAM with billing "temporarily".
- Adding foreign keys to consumer product tables from IAM migrations.
- Claiming extraction complete while tracker items remain open.
