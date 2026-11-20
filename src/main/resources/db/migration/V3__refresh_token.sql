CREATE TABLE refresh_token (
    id                uuid        PRIMARY KEY,
    family_id         uuid        NOT NULL,
    principal_id      uuid        NOT NULL REFERENCES principal (id) ON DELETE CASCADE,
    token_hash        bytea       NOT NULL,
    family_started_at timestamptz NOT NULL,
    issued_at         timestamptz NOT NULL,
    expires_at        timestamptz NOT NULL,
    used_at           timestamptz,
    revoked_at        timestamptz,
    revoked_reason    text,
    CONSTRAINT refresh_token_hash_uq  UNIQUE (token_hash),
    CONSTRAINT refresh_token_hash_chk CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_token_time_chk CHECK (issued_at <= expires_at AND family_started_at <= issued_at)
);
CREATE INDEX refresh_token_family_idx    ON refresh_token (family_id);
CREATE INDEX refresh_token_principal_idx ON refresh_token (principal_id);
CREATE INDEX refresh_token_expires_idx   ON refresh_token (expires_at);
