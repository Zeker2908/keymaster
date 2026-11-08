CREATE TABLE principal (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind       text        NOT NULL,
    login      text        NOT NULL,
    status     text        NOT NULL DEFAULT 'ACTIVE',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT principal_kind_chk   CHECK (kind IN ('USER', 'CLIENT')),
    CONSTRAINT principal_status_chk CHECK (status IN ('ACTIVE', 'DISABLED')),
    CONSTRAINT principal_login_chk  CHECK (login ~ '^[a-z0-9._-]{3,32}$'),
    CONSTRAINT principal_login_uq   UNIQUE (login)
);

CREATE TABLE credential (
    principal_id uuid        PRIMARY KEY REFERENCES principal (id) ON DELETE CASCADE,
    secret_hash  text        NOT NULL,
    changed_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT credential_hash_chk CHECK (secret_hash LIKE '$argon2id$%')
);

CREATE TABLE role (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text        NOT NULL,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT role_name_chk CHECK (name ~ '^[a-z0-9][a-z0-9._:-]{0,63}$'),
    CONSTRAINT role_name_uq  UNIQUE (name)
);

INSERT INTO role (name, description)
VALUES ('admin', 'Full administrative access to keymaster');

CREATE TABLE principal_role (
    principal_id uuid        NOT NULL REFERENCES principal (id) ON DELETE CASCADE,
    role_id      uuid        NOT NULL REFERENCES role (id) ON DELETE RESTRICT,
    assigned_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (principal_id, role_id)
);
CREATE INDEX principal_role_role_idx ON principal_role (role_id);

CREATE TABLE audit_log (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_id    uuid,
    action      text        NOT NULL,
    target_type text        NOT NULL,
    target_id   text        NOT NULL,
    details     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id  text,
    CONSTRAINT audit_action_chk  CHECK (action ~ '^[a-z_]+\.[a-z_]+$'),
    CONSTRAINT audit_details_chk CHECK (jsonb_typeof(details) = 'object')
);
CREATE INDEX audit_log_target_idx ON audit_log (target_type, target_id, at);
CREATE INDEX audit_log_at_idx     ON audit_log (at DESC);

CREATE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();