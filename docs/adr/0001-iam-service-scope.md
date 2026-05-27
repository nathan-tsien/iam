# ADR-0001: IAM service scope

## Status

Accepted

## Context

The family-office-platform backend contains a mature authentication and user-management module (JWT sessions, OTP email verification, refresh-token rotation, admin disable/enable, profile and avatar self-service).

Multiple product MVPs (family-office, ash, future apps) need the same IAM capabilities without duplicating code or coupling product databases to auth tables.

Extraction plan: [docs/migration/extraction-plan.md](../migration/extraction-plan.md).

## Decision

This repository scope **ONLY** includes:

| Area | Endpoints / capabilities |
|------|--------------------------|
| Authentication | register, check-availability, OTP verify, login, refresh, logout, password forgot/reset |
| Account self-service | `GET/PATCH /v1/me`, avatar presign/commit |
| Admin user management | list, search, disable, enable, trigger password reset |
| Internal integration | HMAC-protected user lookup, batch lookup, exists; webhook fan-out to consumers |

Explicitly **OUT of scope** (reject in review):

- Subscription, billing, payments, entitlements
- Product business logic (projects, skills, agent chat, agent memory, approvals, notifications, ...)
- OAuth / SSO provider implementations (add via future provider ADRs only)
- Tenancy and multi-region routing (JWT claim extensions deferred to ADR-0002+)
- Consumer-side `users_local` cache (owned by each product repo)

## Consequences

- **Easier:** One IAM deployment shared by many products; clear PR boundary for agents and humans.
- **Harder:** No FK from consumer tables to `iam.users`; consistency via webhooks + local cache + reconciliation jobs.
- **Trade-off:** Phase 1 shares `JWT_SECRET` with consumers for local token verify; migrate to JWKS in a later ADR to remove shared secrets.

## Related

- [ARCHITECTURE.md](../../ARCHITECTURE.md)
- [docs/migration/tracker.md](../migration/tracker.md)
