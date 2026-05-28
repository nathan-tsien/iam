# IAM Implementation Tracker

> Source of truth for IAM initial implementation in this repository.
> Plan reference: [implementation-path.md](./implementation-path.md) (incremental waves; ADR on demand)
> Legacy: [extraction-plan.md](./extraction-plan.md) (Superpower plan; pending rewrite)
> Update on every state transition; commit alongside the change being tracked.

## Overview

- Start date: 2026-05-27
- Current phase: Phase 1 (Wave 4 complete)
- Progress: 6 / 19
- Last updated: 2026-05-29 (Wave 4 complete)

## Phase 0 · Design decisions (0.5d)

- [x] **P0-T1** multi-app-adr — Per-app user pools, identity schema, sessions, login history, self-delete, iamctl, super-admin
  - status: done
  - blocked-by: ·
  - started: 2026-05-27
  - finished: 2026-05-27
  - commit: ·
  - PR: ·
  - artifact: `docs/adr/0002-multi-app-and-identity-model.md`
  - note: Supersedes ADR-0001 tenancy deferral only.

- [ ] **P0-T2** db-topology-adr — **Optional / on demand** — Write ADR-0003 only if DB topology assumptions change (see [implementation-path.md](./implementation-path.md))
  - status: deferred
  - blocked-by: ·
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - artifact: `docs/adr/0003-db-topology.md` (if triggered)
  - note: Default assumptions documented in implementation-path.md; Wave 1 proceeds without ADR-0003.

## Phase 1 · IAM service implementation (3-5d)

- [x] **P1-T1** scaffold-iam-repo — Repository + Go module bootstrap
  - status: done
  - blocked-by: ·
  - started: 2026-05-27
  - finished: 2026-05-27
  - commit: nathan-tsien/iam@294eb7e
  - PR: ·
  - note: Bootstrap commit — docs, skeleton dirs, go.mod, tracker.

- [x] **P1-T2** baseline-migration — `apps`, `users` (with `app_id`), `user_identities` (create only), `super_admins`, `login_events`, extended `refresh_tokens`
  - status: done
  - blocked-by: ·
  - started: 2026-05-27
  - finished: 2026-05-27
  - commit: nathan-tsien/iam@0694060
  - PR: ·
  - note: Goose migration `00001_baseline.sql`; seeds system app `_iam`.

- [x] **P1-T3** iamctl — `cmd/iamctl`: `apps create|list|disable`, `super-admins grant`
  - status: done
  - blocked-by: ·
  - started: 2026-05-27
  - finished: 2026-05-27
  - commit: nathan-tsien/iam@0694060
  - PR: ·
  - note: Separate binary; per-app HMAC secret printed once on create.

- [x] **P1-T4** lift-auth-modules — Lift auth/otp from source; drop product fields (`agent_memory_paused`, `tier`); scope all queries by `app_id`
  - status: done
  - blocked-by: P1-T2
  - started: 2026-05-28
  - finished: 2026-05-28
  - commit: worktree-wave2-auth
  - PR: ·
  - note: Lifted internal/auth, repo/user, repo/refresh, service/auth, service/otp. Userprofile/useradmin deferred to Wave 4.

- [x] **P1-T5** iam-cmd-main — Wire `cmd/api/main.go` with app-slug middleware, JWT `aud`, auth service
  - status: done
  - blocked-by: P1-T4
  - started: 2026-05-28
  - finished: 2026-05-28
  - commit: worktree-wave2-auth
  - PR: ·
  - note: ·

- [ ] **P1-T6** iam-openapi-slice — OpenAPI under `/v1/apps/{slug}/...`; codegen; app-scoped + super-admin admin routes
  - status: todo
  - blocked-by: P1-T5
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P1-T7** sessions-and-account — Sessions list/revoke, login history, self-delete (soft + anonymize + webhook)
  - status: todo
  - blocked-by: P1-T5
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: `login_events` writes are non-blocking.

- [ ] **P1-T8** iam-internal-api — Per-app HMAC internal user API + webhook outbox + retry job
  - status: todo
  - blocked-by: P1-T6
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Replaces global `INTERNAL_HMAC_SECRET` with per-app secrets.

## Phase 2 · Consumer integration (2-3d)

Work below happens in **consumer application repositories**, not in this repo. Tracked here for cutover coordination only.

- [ ] **P2-T1** iamclient-package — HMAC client scoped to app slug, timeout/retry, optional LRU cache
  - status: todo
  - blocked-by: P1-T8
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Consumer repo.

- [ ] **P2-T2** users-local-table — Local cache table + repo mirroring IAM user read paths
  - status: todo
  - blocked-by: P2-T1
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Consumer repo.

- [ ] **P2-T3** user-extensions-table — Product-specific user fields in consumer DB (not IAM)
  - status: todo
  - blocked-by: P2-T2
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Consumer repo.

- [ ] **P2-T4** webhook-receiver — `POST /internal/webhooks/iam` (HMAC verify + idempotent `event_id`)
  - status: todo
  - blocked-by: P2-T2
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Consumer repo.

- [ ] **P2-T5** rewrite-callers — Replace direct user repo reads with `users_local`
  - status: todo
  - blocked-by: P2-T3, P2-T4
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Consumer repo.

- [ ] **P2-T6** remove-local-iam — Delete local auth/otp/profile/admin modules and auth HTTP routes
  - status: todo
  - blocked-by: P2-T5
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Consumer repo.

- [ ] **P2-T7** jwt-verify-only — Consumer middleware uses verify-only Signer; validates JWT `aud` for its app
  - status: todo
  - blocked-by: P2-T6
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: Consumer repo.

## Phase 3 · Data cutover (1d)

- [ ] **P3-T1** staging-cutover — Deploy IAM service, migrate user data into `iam.users` per app, point frontend auth to IAM
  - status: todo
  - blocked-by: P2-T7
  - started: ·
  - finished: ·
  - commit: ·
  - PR: ·
  - note: ·

- [ ] **P3-T2** deprecate-legacy-tables — Drop redundant auth tables in consumer DB + post-cutover boundary ADR
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
