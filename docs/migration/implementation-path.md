# IAM Implementation Path

Incremental delivery plan for this repository. **Write code only after this document and the tracker agree on the current wave.**

Companion artifacts:

- [tracker.md](./tracker.md) — task status (update on every state change)
- [ADR-0002](../adr/0002-multi-app-and-identity-model.md) — accepted multi-app tenancy (hard constraint)
- [extraction-plan.md](./extraction-plan.md) — Superpower plan (Chinese; pending structural rewrite)

## Principles

| Principle | Rule |
|-----------|------|
| Vertical slices | Each wave must compile, pass `make test`, and support manual verification (curl or integration test). |
| ADR on demand | Do **not** write preventive ADRs. Stop and draft an ADR only when two or more viable options exist and the wrong choice would break schema or HTTP contracts. |
| Repository boundary | Phase 2 consumer work happens in consumer application repositories. This repo implements the IAM service only. |
| Done definition | Wave complete when: `make lint`, `make test` green; tracker updated; commit references the wave. |

## Current position

```
Done:  Waves 1–5 + OpenAPI codegen migration
Next:  Wave 6 — webhook outbox, dispatch worker
```

## Working assumptions (not yet ADR-0003)

The following defaults apply until a decision forces ADR-0003:

- Shared Postgres instance, IAM data in the **`iam` schema** (consumer apps use their own schema).
- Admin IAM actions write to **`iam.audit_logs`** (scheme A: audit owned by IAM).
- Phase 1 uses a **shared `JWT_SECRET`** with consumers; access tokens include **`aud`** per app (ADR-0002). JWKS / RS256 is deferred.

If any of these change (dedicated DB, audit elsewhere, immediate JWKS), stop and write ADR-0003 before continuing migrations.

---

## Wave 1 · Infrastructure (0.5–1 day)

**Goal:** Database migrates cleanly; `iamctl` registers the first app; API process starts (health check only).

| Step | Tracker | Deliverable |
|------|---------|-------------|
| 1.1 | — | Go module dependencies; skeleton packages (`internal/config`, `internal/repo`, …). |
| 1.2 | — | Migration runner (match the source codebase tool if one exists; otherwise choose once and document in tracker note). |
| 1.3 | **P1-T2** | Baseline migration: `apps`, `users` (`app_id`), `user_identities` (empty), `super_admins`, `login_events`, extended `refresh_tokens`; seed system app `_iam`. |
| 1.4 | **P1-T3** | `cmd/iamctl`: `apps create|list|disable`, `super-admins grant`. |
| 1.5 | — | Minimal `cmd/api`: config load, DB connect, `GET /healthz` on port 8090. |

**Exit criteria**

- `make migrate-up` succeeds on a fresh database.
- `iamctl apps create --slug=demo ...` inserts a row in `iam.apps`.
- `curl localhost:8090/healthz` returns 200.

**ADR gate:** none, unless DB topology assumptions are challenged.

---

## Wave 2 · Auth vertical slice (1–1.5 days)

**Goal:** One app runs **register → OTP verify → login → refresh**; JWT includes correct `aud`; cross-app isolation enforced.

| Step | Tracker | Deliverable |
|------|---------|-------------|
| 2.1 | **P1-T4** (partial) | Lift `internal/auth`, `repo/user`, `repo/refresh`, `repo/otp`; drop product fields; scope all queries by `app_id`. |
| 2.2 | — | App slug middleware: resolve `{slug}` → `apps` row; reject disabled apps. |
| 2.3 | **P1-T5** (partial) | Wire auth + otp services; routes for register, OTP verify, login, refresh only. |
| 2.4 | — | JWT signing with `aud = app.jwt_audience`; bearer middleware validates `aud`. |
| 2.5 | — | Repo and service tests: happy paths, duplicate registration, bad OTP, cross-app token rejection. |

**Exit criteria**

- End-to-end auth for app `demo` via curl or integration test.
- Token minted for `demo` rejected when used against another app slug.

**Defer:** OpenAPI / oapi-codegen until Wave 6 (hand-written or minimal Gin routes first).

**ADR gate:** none.

---

## Wave 3 · Auth completion (0.5–1 day)

**Goal:** Full public auth surface from ADR-0001 scope.

| Step | Deliverable |
|------|-------------|
| 3.1 | Logout, check-availability, password forgot / reset. |
| 3.2 | Mail provider (SMTP + log mailer for development). |
| 3.3 | Rate limiting (Redis with in-memory fallback). |
| 3.4 | Best-effort `login_events` inserts on login success / failure (must not fail the HTTP response). |

**Exit criteria:** All auth endpoints covered by tests; rate limits exercised in at least one test.

**ADR gate:** none.

---

## Wave 4 · Self-service and per-app admin (1 day)

**Goal:** `/me`, avatar, and app-scoped admin user management.

| Step | Deliverable |
|------|-------------|
| 4.1 | Lift `userprofile` service; avatar presign / commit with storage config. |
| 4.2 | Lift `useradmin` (list, search, disable, enable, trigger password reset); strict per-app RBAC. |
| 4.3 | `audit_logs` writes for admin actions. |

**Exit criteria:** `/v1/apps/{slug}/me` and `/v1/apps/{slug}/users/*` admin flows tested.

**ADR gate:** none.

---

## Wave 5 · Sessions, history, account deletion (0.5–1 day)

**Tracker:** **P1-T7**

| Step | Deliverable |
|------|-------------|
| 5.1 | `GET /v1/apps/{slug}/me/sessions`, `DELETE .../sessions/{id}`, optional revoke-all. |
| 5.2 | `GET /v1/apps/{slug}/me/login-history` (paginated). |
| 5.3 | `DELETE /v1/apps/{slug}/me` — soft delete, PII anonymization, revoke tokens, enqueue webhook. |

**Exit criteria:** Three endpoint groups tested; delete anonymizes email and revokes sessions.

**ADR gate (optional):** If webhook event shape for `user.deleted` conflicts with consumer expectations, stop and write a short ADR or OpenAPI note before shipping.

---

## Wave 6 · Contract and internal integration (1–1.5 days)

**Tracker:** **P1-T6**, **P1-T8**

| Step | Deliverable |
|------|-------------|
| 6.1 | OpenAPI slice under `/v1/apps/{slug}/...`; oapi-codegen; replace hand-written handlers. |
| 6.2 | Super-admin routes `/v1/admin/*` with `_iam` app + `super_admins` membership check. |
| 6.3 | Per-app HMAC internal API: user get, batch lookup, exists. |
| 6.4 | Webhook outbox table + retry worker; sign with per-app secret; route to `apps.webhook_url`. |

**Exit criteria:** OpenAPI is the contract source; internal API and webhook paths have integration tests.

**Phase 1 complete** for this repository.

**ADR gates**

| Topic | When to stop |
|-------|----------------|
| Webhook delivery | Retry policy, DLQ, or at-least-once semantics disputed before outbox implementation. |
| HMAC wire format | Incompatible with existing consumer middleware; document before coding. |

---

## After Phase 1 (coordination only)

These tracker phases are **not implemented in this repo**:

| Phase | Scope |
|-------|--------|
| Phase 2 | Consumer: `iamclient`, `users_local`, webhook receiver, remove local IAM modules, JWT verify-only + `aud` check. |
| Phase 3 | Staging cutover, per-app user data migration, deprecate legacy auth tables. |
| Phase 4+ | SMS and OAuth providers (ADR-0004, ADR-0005); billing (separate plan). |

---

## ADR trigger registry

| ID | Topic | Trigger | Write now? |
|----|-------|---------|------------|
| ADR-0003 | DB topology | Dedicated DB, schema split change, or audit ownership change | No — use working assumptions above |
| ADR-0004 | SMS providers | Start phone registration / SMS OTP | No — Phase 1 schema only |
| ADR-0005 | OAuth providers | Choose first providers and account-linking rules | No — Phase 1 schema only |
| ADR-0006 | JWKS / RS256 | Remove shared `JWT_SECRET` | No — after Phase 1 stable |
| Short ADR | Webhook contract | Payload or event names blocked in Wave 5–6 | When triggered |
| Short ADR | Cutover boundary | Legacy table drop policy disputed in Phase 3 | When triggered |

---

## Suggested execution order

```text
Wave 1  P1-T2 → P1-T3 → cmd/api health
Wave 2  P1-T4 (slice) → P1-T5 (slice) + tests
Wave 3  auth completion
Wave 4  me + per-app admin
Wave 5  P1-T7
Wave 6  P1-T6 → P1-T8
Pause   consumer Phase 2 (other repositories)
```

Update [tracker.md](./tracker.md) when starting or finishing each wave. Mark **P0-T2** done only if ADR-0003 is written; otherwise leave it cancelled or note "assumptions documented in implementation-path.md".
