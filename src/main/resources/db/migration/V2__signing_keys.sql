CREATE TABLE signing_key (
    kid                text        PRIMARY KEY,
    alg                text        NOT NULL,
    public_key         bytea       NOT NULL,
    private_key_enc    bytea       NOT NULL,
    nonce              bytea       NOT NULL,
    master_key_version smallint    NOT NULL DEFAULT 1,
    created_at         timestamptz NOT NULL,
    publish_at         timestamptz NOT NULL,
    activate_at        timestamptz NOT NULL,
    retire_at          timestamptz,
    remove_at          timestamptz,
    revoked_at         timestamptz,
    CONSTRAINT signing_key_kid_chk   CHECK (kid ~ '^[A-Za-z0-9_-]{43}$'),
    CONSTRAINT signing_key_nonce_chk CHECK (octet_length(nonce) = 12),
    CONSTRAINT signing_key_order_chk CHECK (
        publish_at <= activate_at
        AND (retire_at IS NULL OR activate_at <= retire_at)
        AND (remove_at IS NULL OR (retire_at IS NOT NULL AND retire_at <= remove_at))
    ),
    CONSTRAINT signing_key_single_signer
        EXCLUDE USING gist (tstzrange(activate_at, retire_at) WITH &&),
    CONSTRAINT signing_key_revoked_retired_chk
        CHECK (revoked_at IS NULL
               OR (retire_at IS NOT NULL AND retire_at <= GREATEST(revoked_at, activate_at)))
);