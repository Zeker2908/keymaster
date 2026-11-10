package ru.zeker.keymaster.resource;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.vertx.core.buffer.Buffer;
import io.vertx.mutiny.sqlclient.Row;
import io.vertx.mutiny.sqlclient.Tuple;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.IntegrationTestBase;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.key.KeyTimeline;
import ru.zeker.keymaster.domain.key.codec.RsaKeyCodec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class JwksResourceIntegrationTest extends IntegrationTestBase {

    private static final Duration HOUR = Duration.ofHours(1);
    private static final int MAX_PUBLISHED_KEYS = 50;
    private static final int KEY_PAIR_COUNT = 3;

    private static List<TestKey> testKeys;

    private final List<StoredKey> keysBeforeTest = new ArrayList<>();

    @BeforeAll
    static void generateKeyPairs() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        List<TestKey> keys = new ArrayList<>(KEY_PAIR_COUNT);
        for (int i = 0; i < KEY_PAIR_COUNT; i++) {
            KeyPair keyPair = generator.generateKeyPair();
            keys.add(new TestKey(
                    RsaKeyCodec.toSpki(keyPair.getPublic()),
                    (RSAPublicKey) keyPair.getPublic()));
        }

        testKeys = List.copyOf(keys);
    }

    @BeforeEach
    void resetSigningKeys() {
        keysBeforeTest.clear();
        keysBeforeTest.addAll(loadSigningKeys());
        pool.query("DELETE FROM keymaster.signing_key").execute().await().atMost(TIMEOUT);
    }

    @AfterEach
    void restoreSigningKeys() {
        pool.query("DELETE FROM keymaster.signing_key").execute().await().atMost(TIMEOUT);
        keysBeforeTest.forEach(this::insertStoredKey);
        keysBeforeTest.clear();
    }

    @Test
    void returnsOnlyPublishedPublicRsaKeysWithNoCache() throws Exception {
        Instant now = Instant.now();

        String activeKid = randomKid();
        String plannedKid = randomKid();
        String retiredKid = randomKid();
        String pendingKid = randomKid();
        String removedKid = randomKid();
        String revokedKid = randomKid();

        TestKey activeKey = testKeys.get(0);
        TestKey plannedKey = testKeys.get(1);
        TestKey retiredKey = testKeys.get(2);

        insertKey(activeKid, new KeyTimeline(
                now.minus(HOUR.multipliedBy(3)),
                now.minus(HOUR.multipliedBy(2)),
                now.plus(HOUR),
                now.plus(HOUR.multipliedBy(2)),
                null), activeKey);
        insertKey(plannedKid, new KeyTimeline(
                now.minus(HOUR),
                now.plus(HOUR),
                now.plus(HOUR.multipliedBy(2)),
                now.plus(HOUR.multipliedBy(3)),
                null), plannedKey);
        insertKey(retiredKid, new KeyTimeline(
                now.minus(HOUR.multipliedBy(6)),
                now.minus(HOUR.multipliedBy(5)),
                now.minus(HOUR.multipliedBy(4)),
                now.plus(HOUR.multipliedBy(5)),
                null), retiredKey);
        insertKey(pendingKid, new KeyTimeline(
                now.plus(HOUR),
                now.plus(HOUR.multipliedBy(2)),
                now.plus(HOUR.multipliedBy(3)),
                now.plus(HOUR.multipliedBy(4)),
                null), activeKey);
        insertKey(removedKid, new KeyTimeline(
                now.minus(HOUR.multipliedBy(9)),
                now.minus(HOUR.multipliedBy(8)),
                now.minus(HOUR.multipliedBy(7)),
                now.minus(HOUR.multipliedBy(6)),
                null), plannedKey);
        insertKey(revokedKid, new KeyTimeline(
                now.minus(HOUR.multipliedBy(12)),
                now.minus(HOUR.multipliedBy(11)),
                now.minus(HOUR.multipliedBy(10)),
                now.minus(HOUR.multipliedBy(9)),
                now.minus(HOUR.multipliedBy(8))), retiredKey);

        Response response = given()
                .when()
                .get("/jwks");

        assertEquals(200, response.statusCode(), response.asString());
        assertTrue(response.contentType().startsWith("application/json"), response.contentType());
        assertEquals("no-cache", response.header("Cache-Control"));

        Map<String, TestKey> expectedKeys = Map.of(
                activeKid, activeKey,
                plannedKid, plannedKey,
                retiredKid, retiredKey);

        JWKSet jwks = JWKSet.parse(response.asString());

        assertEquals(expectedKeys.keySet(), kids(jwks));
        assertEquals(3, jwks.getKeys().size());

        for (JWK jwk : jwks.getKeys()) {
            RSAKey rsaKey = assertInstanceOf(RSAKey.class, jwk);
            TestKey expectedKey = expectedKeys.get(rsaKey.getKeyID());

            assertNotNull(expectedKey, () -> "unexpected kid: " + rsaKey.getKeyID());
            assertEquals("RSA", rsaKey.getKeyType().getValue());
            assertEquals("sig", rsaKey.getKeyUse().getValue());
            assertEquals(Algorithm.RS256.name(), rsaKey.getAlgorithm().getName());
            assertFalse(rsaKey.isPrivate());
            assertNull(rsaKey.getPrivateExponent());
            assertEquals(expectedKey.publicKey().getModulus(), rsaKey.getModulus().decodeToBigInteger(),
                    () -> "modulus mismatch for kid " + rsaKey.getKeyID());
            assertEquals(expectedKey.publicKey().getPublicExponent(), rsaKey.getPublicExponent().decodeToBigInteger(),
                    () -> "exponent mismatch for kid " + rsaKey.getKeyID());
        }

        List<Map<String, Object>> serializedKeys = response.jsonPath().getList("keys");
        assertEquals(3, serializedKeys.size());

        Map<String, Map<String, Object>> serializedByKid = new HashMap<>();
        for (Map<String, Object> key : serializedKeys) {
            assertEquals(Set.of("kty", "use", "alg", "kid", "n", "e"), key.keySet(),
                    () -> "unexpected JWK fields: " + key);

            String kid = (String) key.get("kid");
            assertNotNull(kid);
            assertNull(serializedByKid.put(kid, key), () -> "duplicate kid: " + kid);
        }

        assertEquals(expectedKeys.keySet(), serializedByKid.keySet());

        Base64.Decoder base64Url = Base64.getUrlDecoder();

        for (Map.Entry<String, TestKey> expected : expectedKeys.entrySet()) {
            Map<String, Object> key = serializedByKid.get(expected.getKey());
            assertNotNull(key);

            assertEquals("AQAB", key.get("e"), () -> "unexpected exponent for kid " + expected.getKey());

            byte[] modulus = base64Url.decode((String) key.get("n"));

            assertEquals(256, modulus.length,
                    () -> "modulus of kid " + expected.getKey() + " must be exactly 256 bytes");
            assertNotEquals(0, modulus[0],
                    () -> "modulus of kid " + expected.getKey() + " must not start with a zero byte");
            assertArrayEquals(unsignedBytes(expected.getValue().publicKey().getModulus()), modulus,
                    () -> "modulus mismatch for kid " + expected.getKey());
        }
    }

    @Test
    void returnsServiceUnavailableWhenNoKeysArePublished() {
        Instant now = Instant.now();

        insertKey(randomKid(), new KeyTimeline(
                now.plus(HOUR),
                now.plus(HOUR.multipliedBy(2)),
                now.plus(HOUR.multipliedBy(3)),
                null,
                null));

        given()
                .when()
                .get("/jwks")
                .then()
                .statusCode(503)
                .contentType(containsString("application/json"))
                .body("status", equalTo(503))
                .body("error", equalTo("JWK_UNAVAILABLE"))
                .body("message", equalTo("No published signing keys"))
                .body("path", equalTo("/jwks"))
                .body("requestId", notNullValue());
    }

    @Test
    void returnsServiceUnavailableWhenPublishedKeysExceedMaximum() {
        Instant base = Instant.now().minus(Duration.ofDays(2));

        for (int i = 0; i <= MAX_PUBLISHED_KEYS; i++) {
            Instant activateAt = base.minus(HOUR.multipliedBy(i * 2L));

            insertKey(randomKid(), new KeyTimeline(
                    activateAt.minusSeconds(60),
                    activateAt,
                    activateAt.plus(HOUR),
                    null,
                    null));
        }

        given()
                .when()
                .get("/jwks")
                .then()
                .statusCode(503)
                .body("status", equalTo(503))
                .body("error", equalTo("JWK_UNAVAILABLE"))
                .body("message", equalTo("Too many published signing keys"));
    }

    // --- helpers ---

    private static Set<String> kids(JWKSet jwks) {
        Set<String> kids = new HashSet<>();

        for (JWK jwk : jwks.getKeys()) {
            assertNotNull(jwk.getKeyID());
            assertTrue(kids.add(jwk.getKeyID()), () -> "duplicate kid: " + jwk.getKeyID());
        }

        return kids;
    }

    private void insertKey(String kid, KeyTimeline timeline) {
        insertKey(kid, timeline, testKeys.getFirst());
    }

    private void insertKey(String kid, KeyTimeline timeline, TestKey key) {
        insertStoredKey(new StoredKey(
                kid,
                Algorithm.RS256.name(),
                key.spki(),
                new byte[]{1, 2, 3},
                new byte[12],
                (short) 1,
                OffsetDateTime.now(ZoneOffset.UTC),
                toOffset(timeline.publishAt()),
                toOffset(timeline.activateAt()),
                toOffset(timeline.retireAt()),
                toOffset(timeline.removeAt()),
                toOffset(timeline.revokedAt())));
    }

    private void insertStoredKey(StoredKey key) {
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
                        key.revokedAt()}))
                .await().atMost(TIMEOUT);
    }

    private List<StoredKey> loadSigningKeys() {
        return pool.query("""
                        SELECT kid, alg, public_key, private_key_enc, nonce, master_key_version,
                               created_at, publish_at, activate_at, retire_at, remove_at, revoked_at
                        FROM keymaster.signing_key
                        ORDER BY kid
                        """)
                .execute()
                .map(rows -> {
                    List<StoredKey> keys = new ArrayList<>();

                    for (Row row : rows) {
                        keys.add(new StoredKey(
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
                                row.getOffsetDateTime("revoked_at")));
                    }

                    return keys;
                })
                .await().atMost(TIMEOUT);
    }

    private static OffsetDateTime toOffset(Instant instant) {
        return instant == null ? null : OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    private static byte[] unsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();

        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        return bytes;
    }

    private static String randomKid() {
        return (UUID.randomUUID().toString() + UUID.randomUUID())
                .replace("-", "")
                .substring(0, 43);
    }

    private record TestKey(byte[] spki, RSAPublicKey publicKey) {
    }

    private record StoredKey(
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
