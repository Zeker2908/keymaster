package ru.zeker.keymaster;

import io.vertx.core.buffer.Buffer;
import io.vertx.mutiny.sqlclient.Pool;
import io.vertx.mutiny.sqlclient.Row;
import io.vertx.mutiny.sqlclient.Tuple;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Snapshot/restore helpers for {@code keymaster.signing_key} rows.
 *
 * <p>Позволяет тестам, которым нужно временно очистить таблицу signing-ключей,
 * вернуть исходное состояние после завершения теста.</p>
 */
public final class SigningKeyTestStore {

    private static final Duration TIMEOUT = Duration.ofSeconds(20);

    private SigningKeyTestStore() {
    }

    public static List<StoredKey> loadAll(Pool pool) {
        return pool.query("""
                        SELECT kid, alg, public_key, private_key_enc, nonce, master_key_version,
                               created_at, publish_at, activate_at, retire_at, remove_at, revoked_at
                        FROM keymaster.signing_key
                        ORDER BY kid
                        """)
                .execute()
                .map(rows -> {
                    List<StoredKey> keys = new ArrayList<>();

                    rows.forEach(row -> keys.add(toStoredKey(row)));

                    return keys;
                })
                .await().atMost(TIMEOUT);
    }

    public static StoredKey load(Pool pool, String kid) {
        return pool.preparedQuery("""
                        SELECT kid, alg, public_key, private_key_enc, nonce, master_key_version,
                               created_at, publish_at, activate_at, retire_at, remove_at, revoked_at
                        FROM keymaster.signing_key
                        WHERE kid = $1
                        """)
                .execute(Tuple.of(kid))
                .map(rows -> toStoredKey(rows.iterator().next()))
                .await().atMost(TIMEOUT);
    }

    public static void deleteAll(Pool pool) {
        pool.query("DELETE FROM keymaster.signing_key")
                .execute()
                .await().atMost(TIMEOUT);
    }

    public static void delete(Pool pool, String kid) {
        pool.preparedQuery("DELETE FROM keymaster.signing_key WHERE kid = $1")
                .execute(Tuple.of(kid))
                .await().atMost(TIMEOUT);
    }

    public static void insert(Pool pool, StoredKey key) {
        pool.preparedQuery("""
                        INSERT INTO keymaster.signing_key (
                            kid, alg, public_key, private_key_enc, nonce, master_key_version,
                            created_at, publish_at, activate_at, retire_at, remove_at, revoked_at
                        )
                        VALUES (
                            $1, $2, $3::bytea, $4::bytea, $5::bytea, $6::smallint,
                            $7::timestamptz, $8::timestamptz, $9::timestamptz,
                            $10::timestamptz, $11::timestamptz, $12::timestamptz
                        )
                        """)
                .execute(Tuple.from(new Object[]{
                        key.kid(),
                        key.alg(),
                        Buffer.buffer(key.publicKey()),
                        Buffer.buffer(key.privateKeyEnc()),
                        Buffer.buffer(key.nonce()),
                        (int) key.masterKeyVersion(),
                        key.createdAt(),
                        key.publishAt(),
                        key.activateAt(),
                        key.retireAt(),
                        key.removeAt(),
                        key.revokedAt()
                }))
                .await().atMost(TIMEOUT);
    }

    private static StoredKey toStoredKey(Row row) {
        return new StoredKey(
                row.getString("kid"),
                row.getString("alg"),
                row.getBuffer("public_key").getBytes(),
                row.getBuffer("private_key_enc").getBytes(),
                row.getBuffer("nonce").getBytes(),
                row.getShort("master_key_version"),
                row.getOffsetDateTime("created_at"),
                row.getOffsetDateTime("publish_at"),
                row.getOffsetDateTime("activate_at"),
                row.getOffsetDateTime("retire_at"),
                row.getOffsetDateTime("remove_at"),
                row.getOffsetDateTime("revoked_at")
        );
    }

    public record StoredKey(
            String kid,
            String alg,
            byte[] publicKey,
            byte[] privateKeyEnc,
            byte[] nonce,
            short masterKeyVersion,
            OffsetDateTime createdAt,
            OffsetDateTime publishAt,
            OffsetDateTime activateAt,
            OffsetDateTime retireAt,
            OffsetDateTime removeAt,
            OffsetDateTime revokedAt
    ) {
    }
}
