package ru.zeker.keymaster.service.key;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.vertx.VertxContextSupport;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.sqlclient.Tuple;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.IntegrationTestBase;
import ru.zeker.keymaster.SigningKeyTestStore;
import ru.zeker.keymaster.SigningKeyTestStore.StoredKey;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.context.Actor;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.domain.key.KeyTimeline;
import ru.zeker.keymaster.domain.key.SigningKeyData;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Интеграционные тесты кэша signing-ключей.
 *
 * <p>Проверяется реальное поведение Quarkus Cache поверх PostgreSQL:</p>
 * <ul>
 *   <li>первое обращение загружает ключ из БД, повторное обслуживается из кэша;</li>
 *   <li>точечная инвалидация удаляет только один ключ;</li>
 *   <li>{@code invalidateAll} очищает весь кэш;</li>
 *   <li>неудачный поиск не кэшируется;</li>
 *   <li>закэшированные данные совпадают с расшифрованной записью БД.</li>
 * </ul>
 */
@QuarkusTest
class SigningKeyCacheIntegrationTest extends IntegrationTestBase {

    private static final Duration OP_TIMEOUT = Duration.ofSeconds(60);

    @Inject
    SigningKeyCache cache;

    @Inject
    SigningKeyService keys;

    @Inject
    KeyCipher cipher;

    private final List<String> createdKids = new ArrayList<>();

    @BeforeEach
    void clearCacheBeforeTest() throws Throwable {
        run(() -> cache.invalidateAll());
    }

    @AfterEach
    void deleteCreatedKeys() throws Throwable {
        for (String kid : createdKids) {
            SigningKeyTestStore.delete(pool, kid);
        }
        createdKids.clear();
        run(() -> cache.invalidateAll());
    }

    @Test
    void servesCachedKeyAfterDatabaseRowIsRemoved() throws Throwable {
        String kid = createKey(Algorithm.RS256, "2000-01-01");

        SigningKeyData loaded = run(() -> cache.get(kid));
        byte[] privateKey = loaded.privateKey().getEncoded();

        assertEquals(kid, loaded.kid());
        assertEquals(Algorithm.RS256, loaded.algorithm());
        assertNotNull(loaded.privateKey());

        SigningKeyTestStore.delete(pool, kid);

        SigningKeyData cached = run(() -> cache.get(kid));

        assertEquals(kid, cached.kid());
        assertEquals(Algorithm.RS256, cached.algorithm());
        assertArrayEquals(privateKey, cached.privateKey().getEncoded(),
                "повторное обращение должно вернуть ключ из кэша, а не из БД");

        run(() -> cache.invalidate(kid));

        assertKeyNotFound(() -> cache.get(kid));
    }

    @Test
    void invalidatesOnlyRequestedKey() throws Throwable {
        String rsaKid = createKey(Algorithm.RS256, "2000-02-01");
        String ecKid = createKey(Algorithm.ES256, "2000-02-02");

        run(() -> cache.get(rsaKid));
        run(() -> cache.get(ecKid));

        SigningKeyTestStore.delete(pool, rsaKid);
        SigningKeyTestStore.delete(pool, ecKid);

        assertEquals(Algorithm.RS256, run(() -> cache.get(rsaKid)).algorithm());
        assertEquals(Algorithm.ES256, run(() -> cache.get(ecKid)).algorithm());

        run(() -> cache.invalidate(rsaKid));

        assertKeyNotFound(() -> cache.get(rsaKid));
        assertEquals(Algorithm.ES256, run(() -> cache.get(ecKid)).algorithm(),
                "инвалидация одного kid не должна очищать остальные ключи");
    }

    @Test
    void invalidateAllDropsEveryCachedKey() throws Throwable {
        String firstKid = createKey(Algorithm.RS256, "2000-03-01");
        String secondKid = createKey(Algorithm.ES384, "2000-03-02");

        run(() -> cache.get(firstKid));
        run(() -> cache.get(secondKid));

        SigningKeyTestStore.delete(pool, firstKid);
        SigningKeyTestStore.delete(pool, secondKid);

        assertEquals(Algorithm.RS256, run(() -> cache.get(firstKid)).algorithm());
        assertEquals(Algorithm.ES384, run(() -> cache.get(secondKid)).algorithm());

        run(() -> cache.invalidateAll());

        assertKeyNotFound(() -> cache.get(firstKid));
        assertKeyNotFound(() -> cache.get(secondKid));
    }

    @Test
    void doesNotCacheFailedLookups() throws Throwable {
        String kid = createKey(Algorithm.RS256, "2000-04-01");
        StoredKey stored = SigningKeyTestStore.load(pool, kid);

        SigningKeyTestStore.delete(pool, kid);

        assertKeyNotFound(() -> cache.get(kid));

        SigningKeyTestStore.insert(pool, stored);

        SigningKeyData loaded = run(() -> cache.get(kid));

        assertEquals(kid, loaded.kid());
        assertEquals(Algorithm.RS256, loaded.algorithm(),
                "после появления строки в БД ключ должен загрузиться без ручной инвалидации");
    }

    @Test
    void cachedValueMatchesEncryptedDatabaseRecord() throws Throwable {
        String kid = createKey(Algorithm.ES384, "2000-05-01");
        StoredKey stored = SigningKeyTestStore.load(pool, kid);

        SigningKeyData cached = run(() -> cache.get(kid));

        byte[] decrypted = cipher.decrypt(new EncryptedKey(
                stored.privateKeyEnc(),
                stored.nonce(),
                stored.masterKeyVersion()), kid);

        assertEquals(Algorithm.ES384.name(), stored.alg());
        assertEquals(Algorithm.ES384, cached.algorithm());
        assertArrayEquals(decrypted, cached.privateKey().getEncoded(),
                "кэш должен хранить расшифрованный приватный ключ, совпадающий с БД");
        assertEquals(1, (int) stored.masterKeyVersion());
        assertEquals(12, stored.nonce().length);
    }

    // --- helpers ---

    private String createKey(Algorithm algorithm, String date) throws Throwable {
        Instant start = Instant.parse(date + "T00:00:00Z");
        KeyTimeline timeline = new KeyTimeline(
                start,
                start.plusSeconds(600),
                start.plusSeconds(1200),
                null,
                null);

        run(() -> keys.createKey(Actor.SYSTEM, timeline, algorithm));

        String kid = pool.preparedQuery("""
                        SELECT kid
                        FROM keymaster.signing_key
                        WHERE publish_at = $1
                          AND activate_at = $2
                        """)
                .execute(Tuple.of(
                        OffsetDateTime.ofInstant(timeline.publishAt(), ZoneOffset.UTC),
                        OffsetDateTime.ofInstant(timeline.activateAt(), ZoneOffset.UTC)))
                .map(rows -> rows.iterator().next().getString("kid"))
                .await().atMost(TIMEOUT);

        createdKids.add(kid);
        return kid;
    }

    private void assertKeyNotFound(Supplier<Uni<SigningKeyData>> lookup) {
        Throwable failure = assertThrows(Throwable.class, () -> run(lookup));

        KeyMasterException domain = findCause(failure, KeyMasterException.class);
        assertNotNull(domain, () -> "ожидалась доменная ошибка, получено: " + failure);
        assertEquals(ErrorCode.KEY_NOT_FOUND, domain.getCode());
    }

    private static <T> T run(Supplier<Uni<T>> supplier) throws Throwable {
        return VertxContextSupport.subscribeAndAwait(() -> supplier.get()
                .ifNoItem()
                .after(OP_TIMEOUT)
                .fail());
    }

    private static <T extends Throwable> T findCause(Throwable failure, Class<T> type) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (type.isInstance(cause)) {
                return type.cast(cause);
            }
        }
        return null;
    }
}
