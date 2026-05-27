# IAM Extraction Tracker

> Source of truth for the IAM extraction from `family-office-platform/backend`.
> Plan reference: [extraction-plan.md](./extraction-plan.md)
> Update on every state transition; commit alongside the change being tracked.

## Overview

- Start date: 2026-05-27
- Current phase: Phase 0
- Progress: 0 / 16
- Last updated: 2026-05-27 by bootstrap

## Phase 0 · Topology decisions (0.5d)

- [ ] **P0-T1** topology-decision — Shared Postgres (two schemas), audit scheme A, phase-1 shared JWT_SECRET
  - status: todo
  - blocked-by: ·
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - artifact: `docs/adr/0001-iam-service-scope.md` + planned ADR-0002 (DB topology)
  - note: ·

## Phase 1 · Carve out iam-service (2-3d)

- [ ] **P1-T1** scaffold-iam-repo — Repository + Go module bootstrap
  - status: todo
  - blocked-by: ·
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Mark done after initial bootstrap commit lands.

- [ ] **P1-T2** trim-user-model — Remove `agent_memory_paused` / `tier` from User model when copying from family-office
  - status: todo
  - blocked-by: P0-T1
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P1-T3** iam-cmd-main — Wire `cmd/api/main.go` (auth, otp, userprofile, useradmin, mail, storage, ratelimit)
  - status: todo
  - blocked-by: P1-T2
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P1-T4** iam-openapi-slice — Slice auth/me/users from family-office OpenAPI + rerun codegen
  - status: todo
  - blocked-by: P1-T3
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P1-T5** iam-internal-api — `/v1/internal/users{,/batchLookup,/exists}` + webhook outbox + retry job
  - status: todo
  - blocked-by: P1-T4
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

## Phase 2 · family-office as consumer (2-3d)

- [ ] **P2-T1** iamclient-package — `internal/iamclient` with HMAC client, timeout/retry, optional LRU cache
  - status: todo
  - blocked-by: P1-T5
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Work happens in family-office-platform repo.

- [ ] **P2-T2** users-local-table — Migration `0093_users_local` + `internal/repo/userslocal`
  - status: todo
  - blocked-by: P2-T1
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P2-T3** user-extensions-table — Migration `0094_user_extensions` for `agent_memory_paused`
  - status: todo
  - blocked-by: P2-T2
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P2-T4** webhook-receiver — `POST /internal/webhooks/iam` (HMAC verify + idempotent `event_id`)
  - status: todo
  - blocked-by: P2-T2
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P2-T5** rewrite-callers — Replace ~10 `userRepo.FindByID` / `ListByIDs` call sites with `userslocal`
  - status: todo
  - blocked-by: P2-T3, P2-T4
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P2-T6** fo-delete-iam-modules — Remove auth/otp/userprofile/useradmin services, refresh repo, auth/me/users httpapi
  - status: todo
  - blocked-by: P2-T5
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P2-T7** fo-license-signer-fix — `license/middleware.go` verify-only Signer (shared JWT_SECRET)
  - status: todo
  - blocked-by: P2-T6
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

## Phase 3 · Data cutover (1d)

- [ ] **P3-T1** staging-cutover — Staging deploy, copy `public.users` → `iam.users`, point frontend auth to iam-service
  - status: todo
  - blocked-by: P2-T7
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P3-T2** deprecate-legacy-tables — Drop redundant tables in family-office + ADR-0002 (post-extraction boundary)
  - status: todo
  - blocked-by: P3-T1
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Observe 1-2 days before drop.

## Phase 4 · Async (separate plan)

- [ ] **P4-T1** billing-followup — License module ownership vs billing-engine (not tracked in this repo)
  - status: todo
  - blocked-by: P3-T2
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

## Template: add a task

Copy into the appropriate phase section:

```md
- [ ] **PX-TY** <slug> — <one-line description>
  - status: todo
  - blocked-by: ·
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·
```
