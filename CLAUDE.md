# CLAUDE.md

Agent guidance for the **iam** repository. **`AGENTS.md` is authoritative**; this file summarizes entry points.

## What this repo is

Standalone Go IAM service. Reusable across multiple independent consumer applications without coupling their databases to authentication tables.

## Read first

1. **`AGENTS.md`** — scope guardrails, layering, testing, forbidden shortcuts
2. **`ARCHITECTURE.md`** — service boundaries and consumer integration
3. **`docs/migration/implementation-path.md`** — incremental waves (coding order)
4. **`docs/migration/tracker.md`** — current extraction progress
5. **`docs/adr/`** — accepted decisions (supersede, do not rewrite history)

## Commands

```bash
make build
make lint
make test
make migrate-up
```

## Inviolable rules (summary)

- IAM only — reject billing, subscriptions, and product business logic in this repo.
- Do not import any consumer application module.
- All repository docs in English, except Superpower spec / plan files (see `AGENTS.md` → Documentation conventions).
- English for code comments and logs; API error messages in English (consumers own i18n).
- Layering: `internal/auth` → `internal/repo` → `internal/service` → `internal/httpapi`.

Conflict resolution: **`AGENTS.md` beats `CLAUDE.md`**.
