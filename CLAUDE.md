# CLAUDE.md

Agent guidance for the **iam** repository. **`AGENTS.md` is authoritative**; this file summarizes entry points.

## What this repo is

Standalone Go IAM service extracted from `family-office-platform/backend`. Reusable across product shells (ash, family-office, future MVPs).

## Read first

1. **`AGENTS.md`** — scope guardrails, layering, testing, forbidden shortcuts
2. **`ARCHITECTURE.md`** — service boundaries and consumer integration
3. **`docs/migration/tracker.md`** — current extraction progress
4. **`docs/adr/`** — accepted decisions (supersede, do not rewrite history)

## Commands

```bash
make build
make lint
make test
make migrate-up
```

## Inviolable rules (summary)

- IAM only — reject billing, subscriptions, and product business logic in this repo.
- Do not import `family-office-platform`, `ash`, or `cogito` modules.
- English for code comments and logs; API error messages in English (consumers own i18n).
- Layering: `internal/auth` → `internal/repo` → `internal/service` → `internal/httpapi`.

Conflict resolution: **`AGENTS.md` beats `CLAUDE.md`**.
