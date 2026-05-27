# ADR-0001: IAM service scope

## Status

Accepted

## Context

A mature authentication and user-management module already exists in a prior production codebase (JWT sessions, OTP email verification, refresh-token rotation, admin disable / enable, profile and avatar self-service). It is ready to be lifted out and reused.

Multiple independent consumer applications need the same IAM capabilities without duplicating code or coupling their product databases to authentication tables.

Implementation plan: [docs/migration/extraction-plan.md](../migration/extraction-plan.md).

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
- OAuth / SSO provider implementations (add via Phase 2+ provider ADRs; schema reserved in Phase 1)
- Multi-region routing (deferred; per-app tenancy decided in ADR-0002)
- Consumer-side `users_local` cache (owned by each product repo)

## Consequences

- **Easier:** One IAM deployment shared by many products; clear PR boundary for agents and humans.
- **Harder:** No FK from consumer tables to `iam.users`; consistency via webhooks + local cache + reconciliation jobs.
- **Trade-off:** Phase 1 shares `JWT_SECRET` with consumers for local token verify; migrate to JWKS in a later ADR to remove shared secrets.

## Related

- [ADR-0002: Multi-app tenancy and identity model](./0002-multi-app-and-identity-model.md)
- [ARCHITECTURE.md](../../ARCHITECTURE.md)
- [docs/migration/tracker.md](../migration/tracker.md)
