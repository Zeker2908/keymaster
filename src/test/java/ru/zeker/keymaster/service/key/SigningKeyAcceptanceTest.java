package ru.zeker.keymaster.service.key;

import io.quarkus.hibernate.reactive.panache.Panache;
import io.quarkus.test.junit.QuarkusMock;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.vertx.VertxContextSupport;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.sqlclient.Row;
import io.vertx.mutiny.sqlclient.Tuple;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.IntegrationTestBase;
import ru.zeker.keymaster.config.KeymasterConfig;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.context.Actor;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.domain.key.KeyHeader;
import ru.zeker.keymaster.domain.key.KeyTimeline;
import ru.zeker.keymaster.domain.key.codec.RsaKeyCodec;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.repository.SigningKeyRepository;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@QuarkusTest
class SigningKeyAcceptanceTest extends IntegrationTestBase {

    private static final Duration OP_TIMEOUT = Duration.ofSeconds(60);
    private static final byte[] PKCS8_PREFIX = {0x30, (byte) 0x82};

    @Inject
    SigningKeyService keys;

    @Inject
    SigningKeyRepository repository;

    @Inject
    KeyCipher cipher;

    @Inject
    KeymasterConfig config;

    private final List<String> createdKids = new ArrayList<>();

    @AfterEach
    void deleteCreatedKeys() {
        for (String kid : createdKids) {
            deleteKey(kid);
        }
        createdKids.clear();
    }

    @Test
    void privateKeyIsEncryptedInDatabaseAndDecryptsToVerifiableKey() throws Throwable {
        KeyTimeline timeline = pastTimeline("2020-01-01T00:00:00Z");
        String kid = createScheduledKey(timeline);

        Row row = keyRow(kid);

        byte[] encryptedPrivateKey = row.getBuffer("private_key_enc").getBytes();
        byte[] nonce = row.getBuffer("nonce").getBytes();
        short version = row.getShort("master_key_version");
        byte[] publicKey = row.getBuffer("public_key").getBytes();

        assertFalse(startsWithPkcs8Prefix(encryptedPrivateKey),
                "private key must be stored encrypted, not as PKCS#8 DER");

        byte[] privateKeyBytes = cipher.decrypt(new EncryptedKey(encryptedPrivateKey, nonce, version), kid);
        assertTrue(startsWithPkcs8Prefix(privateKeyBytes),
                "decrypted private key must be PKCS#8 DER");

        PrivateKey privateKey = RsaKeyCodec.privateFromPkcs8(privateKeyBytes);
        PublicKey storedPublicKey = RsaKeyCodec.publicFromSpki(publicKey);

        byte[] payload = "acceptance-c".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(payload);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(storedPublicKey);
        verifier.update(payload);
        assertTrue(verifier.verify(signature),
                "signature made with decrypted private key must verify with stored public key");
    }

    @Test
    void createKeyRejectsPublishLeadViolationWithoutSideEffects() {
        Instant publishAt = Instant.parse("2020-02-01T00:00:00Z");
        KeyTimeline tooShortLead = KeyTimeline.scheduled(publishAt, publishAt.plusSeconds(1));

        long keysBefore = countKeys();
        long auditsBefore = countAudits();

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> keys.createKey(Actor.SYSTEM, tooShortLead, Algorithm.RS256));

        assertTrue(failure.getMessage().contains("Activation must be scheduled at least"));
        assertEquals(keysBefore, countKeys());
        assertEquals(auditsBefore, countAudits());
    }

    @Test
    void createKeyRejectsScheduleOverlapAsDomainErrorWithoutSideEffects() throws Throwable {
        ensureInitialKey();

        Instant now = Instant.now();
        KeyTimeline overlap = KeyTimeline.scheduled(now.minus(Duration.ofHours(1)), now);

        long keysBefore = countKeys();
        long auditsBefore = countAudits();

        Throwable failure = assertThrows(Throwable.class,
                () -> run(() -> keys.createKey(Actor.SYSTEM, overlap, Algorithm.RS256)));

        KeyMasterException domain = findCause(failure, KeyMasterException.class);
        assertNotNull(domain, () -> "expected domain exception, got: " + failure);
        assertEquals(ErrorCode.KEY_SCHEDULE_CONFLICT, domain.getCode());

        assertEquals(keysBefore, countKeys(), "failed create must not leave a key");
        assertEquals(auditsBefore, countAudits(), "failed create must not leave an audit record");
    }

    @Test
    void successfulCreateKeyWritesSingleAuditRecordWithoutPrivateData() throws Throwable {
        KeyTimeline timeline = pastTimeline("2020-03-01T00:00:00Z");
        String kid = createScheduledKey(timeline);

        assertEquals(1L, count("""
                SELECT count(*) AS c
                FROM keymaster.audit_log
                WHERE target_type = 'signingKey'
                  AND action = 'key.created'
                  AND target_id = $1
                """, kid));

        String details = pool.preparedQuery("""
                        SELECT details::text AS details
                        FROM keymaster.audit_log
                        WHERE target_type = 'signingKey'
                          AND action = 'key.created'
                          AND target_id = $1
                        """)
                .execute(Tuple.of(kid))
                .map(rows -> rows.iterator().next().getString("details"))
                .await().atMost(TIMEOUT);

        Row row = keyRow(kid);
        String encryptedPrivateKey = base64(row.getBuffer("private_key_enc").getBytes());
        String nonce = base64(row.getBuffer("nonce").getBytes());

        assertTrue(details.contains(kid));
        assertFalse(details.toLowerCase(Locale.ROOT).contains("private"));
        assertFalse(details.toLowerCase(Locale.ROOT).contains("nonce"));
        assertFalse(details.contains(encryptedPrivateKey));
        assertFalse(details.contains(nonce));
    }

    @Test
    void listPublishedReturnsOnlyPlannedActiveAndRetiredForMockedClock() throws Throwable {
        Instant base = Instant.parse("2026-06-01T00:00:00Z");
        List<KeyHeader> all = List.of(
                header("pending", base.plus(Duration.ofHours(2)), base.plus(Duration.ofHours(3)),
                        base.plus(Duration.ofHours(4)), null, null),
                header("planned", base.minus(Duration.ofHours(1)), base.plus(Duration.ofHours(1)),
                        base.plus(Duration.ofHours(2)), null, null),
                header("active", base.minus(Duration.ofHours(2)), base.minus(Duration.ofHours(1)),
                        base.plus(Duration.ofHours(1)), null, null),
                header("retired", base.minus(Duration.ofHours(3)), base.minus(Duration.ofHours(2)),
                        base.minus(Duration.ofHours(1)), null, null),
                header("removed", base.minus(Duration.ofHours(4)), base.minus(Duration.ofHours(3)),
                        base.minus(Duration.ofHours(2)), base.minus(Duration.ofHours(1)), null),
                header("revoked", base.minus(Duration.ofHours(5)), base.minus(Duration.ofHours(4)),
                        base.minus(Duration.ofHours(3)), base.minus(Duration.ofHours(2)),
                        base.minus(Duration.ofHours(1)))
        );

        SigningKeyRepository mockedRepository = mock(SigningKeyRepository.class);
        when(mockedRepository.listPublishedCandidates(any()))
                .thenReturn(Uni.createFrom().item(all));
        QuarkusMock.installMockForType(mockedRepository, SigningKeyRepository.class);

        Clock clock = mock(Clock.class);
        when(clock.instant()).thenReturn(
                base,
                base.minus(Duration.ofMinutes(150)),
                base.plus(Duration.ofMinutes(150)));
        QuarkusMock.installMockForType(clock, Clock.class);

        assertEquals(Set.of("planned", "active", "retired"),
                kids(run(() -> keys.listPublished())), "at base instant");
        assertEquals(Set.of("retired", "removed", "revoked"),
                kids(run(() -> keys.listPublished())), "before the first publish");
        assertEquals(Set.of("pending", "planned", "active", "retired"),
                kids(run(() -> keys.listPublished())), "after the first rotation");
    }

    @Test
    void signingKeyRoundTripPreservesEmbeddedTimeline() throws Throwable {
        Instant base = Instant.parse("2020-04-01T00:00:00Z");
        KeyTimeline timeline = new KeyTimeline(
                base,
                base.plusSeconds(600),
                base.plusSeconds(1200),
                base.plusSeconds(1800),
                base.plusSeconds(1900));

        String kid = randomKid();
        createdKids.add(kid);

        SigningKey key = SigningKey.builder()
                .kid(kid)
                .alg(Algorithm.RS256)
                .publicKey(new byte[]{1, 2, 3})
                .privateKeyEnc(new byte[]{4, 5, 6})
                .nonce(new byte[12])
                .masterKeyVersion((short) 1)
                .timeline(timeline)
                .build();

        run(() -> Panache.withTransaction(() -> repository.create(key)).replaceWithVoid());

        SigningKey loaded = run(() -> Panache.withSession(() -> repository.findById(kid)));

        assertNotNull(loaded);
        assertEquals(kid, loaded.getKid());
        assertEquals(Algorithm.RS256, loaded.getAlg());
        assertArrayEquals(key.getPublicKey(), loaded.getPublicKey());
        assertEquals(timeline, loaded.getTimeline(),
                "@Embedded KeyTimeline must round-trip without changing marks");
        assertNotNull(loaded.getCreatedAt());
    }

    @Test
    void privateKeyAndMasterKeyDoNotLeakIntoToStringOrLogs() throws Throwable {
        ensureInitialKey();

        String masterKey = config.keys().masterKey();
        Row row = firstKeyRow();
        String kid = row.getString("kid");
        byte[] privateKeyBytes = cipher.decrypt(new EncryptedKey(
                row.getBuffer("private_key_enc").getBytes(),
                row.getBuffer("nonce").getBytes(),
                row.getShort("master_key_version")), kid);

        SigningKey key = run(() -> Panache.withSession(() -> repository.findById(kid)));
        assertNotNull(key);

        assertSafe(key.toString(),
                masterKey,
                base64(privateKeyBytes),
                hex(privateKeyBytes),
                base64(row.getBuffer("private_key_enc").getBytes()),
                base64(row.getBuffer("nonce").getBytes()));

        assertSafe(cipher.toString(), masterKey);

        CapturingHandler logs = new CapturingHandler();
        Logger root = Logger.getLogger("");
        root.addHandler(logs);
        try {
            KeyTimeline timeline = pastTimeline("2020-05-01T00:00:00Z");
            String createdKid = createScheduledKey(timeline);

            Row created = keyRow(createdKid);
            byte[] createdPrivateKey = cipher.decrypt(new EncryptedKey(
                    created.getBuffer("private_key_enc").getBytes(),
                    created.getBuffer("nonce").getBytes(),
                    created.getShort("master_key_version")), createdKid);

            assertSafe(logs.text(),
                    masterKey,
                    base64(createdPrivateKey),
                    hex(createdPrivateKey),
                    base64(created.getBuffer("private_key_enc").getBytes()),
                    base64(created.getBuffer("nonce").getBytes()));
        } finally {
            root.removeHandler(logs);
        }
    }

    // --- helpers ---

    private void ensureInitialKey() throws Throwable {
        run(() -> keys.ensureInitialKey(Algorithm.RS256));
    }

    private String createScheduledKey(KeyTimeline timeline) throws Throwable {
        run(() -> keys.createKey(Actor.SYSTEM, timeline, Algorithm.RS256));

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

    private Row keyRow(String kid) {
        return pool.preparedQuery("""
                        SELECT kid, public_key, private_key_enc, nonce, master_key_version
                        FROM keymaster.signing_key
                        WHERE kid = $1
                        """)
                .execute(Tuple.of(kid))
                .map(rows -> rows.iterator().next())
                .await().atMost(TIMEOUT);
    }

    private Row firstKeyRow() {
        return pool.query("""
                        SELECT kid, public_key, private_key_enc, nonce, master_key_version
                        FROM keymaster.signing_key
                        ORDER BY created_at
                        LIMIT 1
                        """)
                .execute()
                .map(rows -> rows.iterator().next())
                .await().atMost(TIMEOUT);
    }

    private void deleteKey(String kid) {
        pool.preparedQuery("DELETE FROM keymaster.signing_key WHERE kid = $1")
                .execute(Tuple.of(kid))
                .await().atMost(TIMEOUT);
    }

    private long countKeys() {
        return count("SELECT count(*) AS c FROM keymaster.signing_key");
    }

    private long countAudits() {
        return count("SELECT count(*) AS c FROM keymaster.audit_log");
    }

    private static KeyTimeline pastTimeline(String publishAt) {
        Instant start = Instant.parse(publishAt);
        return new KeyTimeline(
                start,
                start.plusSeconds(1200),
                start.plusSeconds(2400),
                null,
                null);
    }

    private static KeyHeader header(
            String kid,
            Instant publishAt,
            Instant activateAt,
            Instant retireAt,
            Instant removeAt,
            Instant revokedAt) {
        return new KeyHeader(
                kid,
                Algorithm.RS256,
                new byte[]{1},
                new KeyTimeline(publishAt, activateAt, retireAt, removeAt, revokedAt));
    }

    private static Set<String> kids(List<KeyHeader> headers) {
        Set<String> result = new HashSet<>();
        for (KeyHeader header : headers) {
            result.add(header.kid());
        }
        return result;
    }

    private static String randomKid() {
        return (UUID.randomUUID().toString() + UUID.randomUUID())
                .replace("-", "")
                .substring(0, 43);
    }

    private static boolean startsWithPkcs8Prefix(byte[] value) {
        return value.length >= PKCS8_PREFIX.length
                && value[0] == PKCS8_PREFIX[0]
                && value[1] == PKCS8_PREFIX[1];
    }

    private static String base64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte b : value) {
            result.append("%02x".formatted(b));
        }
        return result.toString();
    }

    private static void assertSafe(String text, String... secrets) {
        assertNotNull(text);
        for (String secret : secrets) {
            assertFalse(text.contains(secret), () -> "secret leaked into: " + text);
        }
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

    private static final class CapturingHandler extends Handler {

        private final StringBuilder messages = new StringBuilder();

        private CapturingHandler() {
            setLevel(Level.ALL);
        }

        @Override
        public void publish(LogRecord record) {
            messages.append(record.getLevel())
                    .append(' ')
                    .append(record.getLoggerName())
                    .append(' ')
                    .append(record.getMessage())
                    .append('\n');

            if (record.getThrown() != null) {
                for (Throwable cause = record.getThrown(); cause != null; cause = cause.getCause()) {
                    messages.append(cause).append('\n');
                }
            }
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }

        private String text() {
            return messages.toString();
        }
    }
}
