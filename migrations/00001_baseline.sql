-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS iam;

CREATE TABLE iam.apps (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                       TEXT NOT NULL,
    display_name               TEXT NOT NULL,
    jwt_audience               TEXT NOT NULL,
    hmac_secret_hash           TEXT NOT NULL,
    mail_from_name             TEXT,
    oauth_redirect_allowlist   JSONB NOT NULL DEFAULT '[]'::jsonb,
    webhook_url                TEXT,
    disabled_at                TIMESTAMPTZ,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT apps_slug_key UNIQUE (slug),
    CONSTRAINT apps_jwt_audience_key UNIQUE (jwt_audience)
);

CREATE TABLE iam.users (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id             UUID NOT NULL REFERENCES iam.apps (id),
    email              TEXT NOT NULL,
    email_lower        TEXT NOT NULL,
    password_hash      TEXT,
    role               TEXT NOT NULL DEFAULT 'user',
    display_name       TEXT,
    email_verified_at  TIMESTAMPTZ,
    disabled_at        TIMESTAMPTZ,
    deleted_at         TIMESTAMPTZ,
    avatar_url         TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_role_check CHECK (role IN ('user', 'admin')),
    CONSTRAINT users_app_email_lower_key UNIQUE (app_id, email_lower)
);

CREATE INDEX idx_users_app_id ON iam.users (app_id);

CREATE TABLE iam.user_identities (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES iam.users (id) ON DELETE CASCADE,
    app_id       UUID NOT NULL REFERENCES iam.apps (id),
    kind         TEXT NOT NULL,
    value        TEXT NOT NULL,
    verified_at  TIMESTAMPTZ,
    is_primary   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_identities_app_kind_value_key UNIQUE (app_id, kind, value)
);

CREATE INDEX idx_user_identities_user_id ON iam.user_identities (user_id);

CREATE TABLE iam.super_admins (
    user_id     UUID PRIMARY KEY REFERENCES iam.users (id) ON DELETE CASCADE,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by  UUID REFERENCES iam.users (id)
);

CREATE TABLE iam.refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES iam.users (id) ON DELETE CASCADE,
    app_id          UUID NOT NULL REFERENCES iam.apps (id),
    token_hash      TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by     UUID REFERENCES iam.refresh_tokens (id),
    device_label    TEXT,
    user_agent      TEXT,
    ip              INET,
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user_id ON iam.refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_app_id ON iam.refresh_tokens (app_id);
CREATE UNIQUE INDEX idx_refresh_tokens_token_hash ON iam.refresh_tokens (token_hash);

CREATE TABLE iam.otp_codes (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id       UUID NOT NULL REFERENCES iam.apps (id),
    email_lower  TEXT NOT NULL,
    purpose      TEXT NOT NULL,
    code_hash    TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    consumed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_otp_codes_lookup ON iam.otp_codes (app_id, email_lower, purpose);

CREATE TABLE iam.login_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID REFERENCES iam.users (id) ON DELETE SET NULL,
    app_id       UUID NOT NULL REFERENCES iam.apps (id),
    kind         TEXT NOT NULL,
    ip           INET,
    user_agent   TEXT,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT login_events_kind_check CHECK (
        kind IN ('login_success', 'login_failure', 'logout', 'refresh', 'password_reset')
    )
);

CREATE INDEX idx_login_events_user_app ON iam.login_events (user_id, app_id, occurred_at DESC);

CREATE TABLE iam.audit_logs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id       UUID NOT NULL REFERENCES iam.apps (id),
    actor_id     UUID REFERENCES iam.users (id) ON DELETE SET NULL,
    target_id    UUID REFERENCES iam.users (id) ON DELETE SET NULL,
    action       TEXT NOT NULL,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_app_created ON iam.audit_logs (app_id, created_at DESC);

-- Bootstrap system app for super-admin operators. Rotate the HMAC secret in production.
INSERT INTO iam.apps (
    slug,
    display_name,
    jwt_audience,
    hmac_secret_hash,
    mail_from_name
) VALUES (
    '_iam',
    'IAM System',
    '_iam',
    encode(digest('bootstrap-iam-system-app-change-me', 'sha256'), 'hex'),
    'IAM'
);

-- +goose Down
DROP TABLE IF EXISTS iam.audit_logs;
DROP TABLE IF EXISTS iam.login_events;
DROP TABLE IF EXISTS iam.otp_codes;
DROP TABLE IF EXISTS iam.refresh_tokens;
DROP TABLE IF EXISTS iam.super_admins;
DROP TABLE IF EXISTS iam.user_identities;
DROP TABLE IF EXISTS iam.users;
DROP TABLE IF EXISTS iam.apps;
DROP SCHEMA IF EXISTS iam;
