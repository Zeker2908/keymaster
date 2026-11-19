package ru.zeker.keymaster.service.key;

import io.quarkus.hibernate.reactive.panache.Panache;
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
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.domain.key.KeyTimeline;
import ru.zeker.keymaster.domain.key.SigningKeyData;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyDecryptionException;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.repository.SigningKeyRepository;

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
 * Проверки кэша signing-ключей.
 *
 * <p>Кэш хранит расшифрованные ключи по {@code kid}:</p>
 * <ul>
 *   <li>повторный запрос того же {@code kid} не расшифровывает ключ заново;</li>
 *   <li>{@code invalidate} удаляет только запрошенный ключ;</li>
 *   <li>{@code invalidateAll} очищает весь кэш;</li>
 *   <li>ошибка расшифровки не попадает в кэш;</li>
 *   <li>значение в кэше совпадает с расшифрованной записью в БД.</li>
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
    SigningKeyRepository repository;

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
    void cachesDecryptedKeyByKid() throws Throwable {
        String kid = createKey(Algorithm.RS256, "2000-01-01");
        SigningKey key = load(kid);

        SigningKeyData loaded = run(() -> cache.get(key));
        byte[] privateKey = loaded.privateKey().getEncoded();

        assertEquals(kid, loaded.kid());
        assertEquals(Algorithm.RS256, loaded.algorithm());
        assertNotNull(loaded.privateKey());

        // Запись удалена из БД, а повторно переданная сущность содержит
        // заведомо нерасшифровываемые данные. Кэш должен вернуть первый результат.
        SigningKeyTestStore.delete(pool, kid);

        SigningKeyData cached = run(() -> cache.get(corruptedCopy(key)));

        assertEquals(kid, cached.kid());
        assertEquals(Algorithm.RS256, cached.algorithm());
        assertArrayEquals(privateKey, cached.privateKey().getEncoded(),
                "повторный запрос должен вернуть закэшированный ключ, а не расшифровывать новый");

        run(() -> cache.invalidate(kid));

        assertDecryptionFails(() -> cache.get(corruptedCopy(key)));
    }

    @Test
    void invalidatesOnlyRequestedKey() throws Throwable {
        String rsaKid = createKey(Algorithm.RS256, "2000-02-01");
        String ecKid = createKey(Algorithm.ES256, "2000-02-02");

        SigningKey rsaKey = load(rsaKid);
        SigningKey ecKey = load(ecKid);

        run(() -> cache.get(rsaKey));
        run(() -> cache.get(ecKey));

        SigningKeyTestStore.delete(pool, rsaKid);
        SigningKeyTestStore.delete(pool, ecKid);

        run(() -> cache.invalidate(rsaKid));

        assertDecryptionFails(() -> cache.get(corruptedCopy(rsaKey)));
        assertEquals(Algorithm.ES256, run(() -> cache.get(corruptedCopy(ecKey))).algorithm(),
                "инвалидация одного kid не должна затрагивать остальные ключи");
    }

    @Test
    void invalidateAllDropsEveryCachedKey() throws Throwable {
        String firstKid = createKey(Algorithm.RS256, "2000-03-01");
        String secondKid = createKey(Algorithm.ES384, "2000-03-02");

        SigningKey firstKey = load(firstKid);
        SigningKey secondKey = load(secondKid);

        run(() -> cache.get(firstKey));
        run(() -> cache.get(secondKey));

        SigningKeyTestStore.delete(pool, firstKid);
        SigningKeyTestStore.delete(pool, secondKid);

        assertEquals(Algorithm.RS256, run(() -> cache.get(corruptedCopy(firstKey))).algorithm());
        assertEquals(Algorithm.ES384, run(() -> cache.get(corruptedCopy(secondKey))).algorithm());

        run(() -> cache.invalidateAll());

        assertDecryptionFails(() -> cache.get(corruptedCopy(firstKey)));
        assertDecryptionFails(() -> cache.get(corruptedCopy(secondKey)));
    }

    @Test
    void doesNotCacheFailedLookups() throws Throwable {
        String kid = createKey(Algorithm.RS256, "2000-04-01");
        SigningKey key = load(kid);

        assertDecryptionFails(() -> cache.get(corruptedCopy(key)));

        SigningKeyData loaded = run(() -> cache.get(key));

        assertEquals(kid, loaded.kid());
        assertEquals(Algorithm.RS256, loaded.algorithm(),
                "после неудачной расшифровки кэш должен попытаться загрузить ключ снова");
    }

    @Test
    void cachedValueMatchesEncryptedDatabaseRecord() throws Throwable {
        String kid = createKey(Algorithm.ES384, "2000-05-01");
        StoredKey stored = SigningKeyTestStore.load(pool, kid);
        SigningKey key = load(kid);

        SigningKeyData cached = run(() -> cache.get(key));

        byte[] decrypted = cipher.decrypt(new EncryptedKey(
                stored.privateKeyEnc(),
                stored.nonce(),
                stored.masterKeyVersion()), kid);

        assertEquals(Algorithm.ES384.name(), stored.alg());
        assertEquals(Algorithm.ES384, cached.algorithm());
        assertArrayEquals(decrypted, cached.privateKey().getEncoded(),
                "кэш должен хранить расшифрованное значение из БД");
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

    private SigningKey load(String kid) throws Throwable {
        SigningKey key = run(() -> Panache.withSession(() -> repository.findByKid(kid)));

        assertNotNull(key, () -> "signing key not found in database: " + kid);
        return key;
    }

    /**
     * Копия сущности с тем же {@code kid}, но с данными, которые невозможно расшифровать.
     */
    private static SigningKey corruptedCopy(SigningKey key) {
        return SigningKey.builder()
                .kid(key.getKid())
                .alg(key.getAlg())
                .publicKey(key.getPublicKey())
                .privateKeyEnc(new byte[]{0x00, 0x01, 0x02, 0x03})
                .nonce(new byte[12])
                .masterKeyVersion((short) 1)
                .timeline(key.getTimeline())
                .build();
    }

    private void assertDecryptionFails(Supplier<Uni<SigningKeyData>> lookup) {
        Throwable failure = assertThrows(Throwable.class, () -> run(lookup));

        KeyMasterException domain = findCause(failure, KeyDecryptionException.class);
        assertNotNull(domain, () -> "ожидалась ошибка расшифровки, получено: " + failure);
        assertEquals(ErrorCode.KEY_DECRYPTION_FAILED, domain.getCode());
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
