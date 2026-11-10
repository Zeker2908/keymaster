package ru.zeker.keymaster.bootstrap;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.vertx.VertxContextSupport;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import ru.zeker.keymaster.IntegrationTestBase;
import ru.zeker.keymaster.SigningKeyTestStore;
import ru.zeker.keymaster.SigningKeyTestStore.StoredKey;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.domain.key.KeyHeader;
import ru.zeker.keymaster.domain.key.SigningKeyData;
import ru.zeker.keymaster.domain.key.codec.EcKeyCodec;
import ru.zeker.keymaster.service.jwk.JwksBuilder;
import ru.zeker.keymaster.service.key.KeyCipher;
import ru.zeker.keymaster.service.key.SigningKeyCache;
import ru.zeker.keymaster.service.key.SigningKeyService;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Полный цикл bootstrap-генерации signing-ключа для каждого поддерживаемого алгоритма.
 *
 * <p>Для каждого {@link Algorithm} тест:</p>
 * <ol>
 *   <li>очищает таблицу ключей и вызывает {@link SigningKeyService#ensureInitialKey(Algorithm)}
 *       — тот же путь, который использует bootstrap-инициализатор;</li>
 *   <li>проверяет, что повторный bootstrap не создаёт второй ключ;</li>
 *   <li>проверяет запись в БД: алгоритм, шифрование приватного ключа, nonce и версию мастер-ключа;</li>
 *   <li>загружает ключ через кэш и сверяет расшифрованный приватный ключ с БД;</li>
 *   <li>подписывает и проверяет данные сгенерированной парой;</li>
 *   <li>проверяет, что ключ попадает в published-набор и в JWKS с корректным JWK.</li>
 * </ol>
 */
@QuarkusTest
@TestProfile(BootstrapSigningKeyTestProfile.class)
class BootstrapSigningKeyAlgorithmIntegrationTest extends IntegrationTestBase {

    private static final Duration OP_TIMEOUT = Duration.ofSeconds(90);

    @Inject
    SigningKeyService keys;

    @Inject
    SigningKeyCache cache;

    @Inject
    KeyCipher cipher;

    @Inject
    JwksBuilder jwksBuilder;

    private List<StoredKey> keysBeforeTest;

    @BeforeEach
    void isolateSigningKeys() throws Throwable {
        run(() -> cache.invalidateAll());

        keysBeforeTest = SigningKeyTestStore.loadAll(pool);
        SigningKeyTestStore.deleteAll(pool);
    }

    @AfterEach
    void restoreSigningKeys() throws Throwable {
        SigningKeyTestStore.deleteAll(pool);

        if (keysBeforeTest != null) {
            for (StoredKey key : keysBeforeTest) {
                SigningKeyTestStore.insert(pool, key);
            }
            keysBeforeTest.clear();
        }

        run(() -> cache.invalidateAll());
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(Algorithm.class)
    void bootstrapCreatesUsableKeyForAlgorithm(Algorithm algorithm) throws Throwable {
        assertTrue(run(() -> keys.ensureInitialKey(algorithm)),
                "первый bootstrap должен создать ключ");
        assertFalse(run(() -> keys.ensureInitialKey(algorithm)),
                "повторный bootstrap не должен создавать второй ключ");
        assertEquals(1L, count("SELECT count(*) AS c FROM keymaster.signing_key"));

        String kid = singleKeyKid();
        StoredKey stored = SigningKeyTestStore.load(pool, kid);

        assertEquals(algorithm.name(), stored.alg());
        assertEquals(43, stored.kid().length(), "kid должен быть SHA-256 thumbprint в base64url");
        assertEquals(12, stored.nonce().length);
        assertEquals(1, (int) stored.masterKeyVersion());

        byte[] decryptedPrivateKey = cipher.decrypt(new EncryptedKey(
                stored.privateKeyEnc(),
                stored.nonce(),
                stored.masterKeyVersion()), kid);

        assertFalse(Arrays.equals(stored.privateKeyEnc(), decryptedPrivateKey),
                "приватный ключ должен храниться в БД в зашифрованном виде");
        assertEquals(0x30, decryptedPrivateKey[0] & 0xFF,
                "расшифрованный приватный ключ должен быть DER-структурой PKCS#8");
        assertNotNull(algorithm.getPrivateKeyDecoder().apply(decryptedPrivateKey));

        SigningKeyData cached = run(() -> cache.get(kid));

        assertEquals(kid, cached.kid());
        assertEquals(algorithm, cached.algorithm());
        assertArrayEquals(decryptedPrivateKey, cached.privateKey().getEncoded(),
                "кэш должен вернуть тот же приватный ключ, что расшифрован из БД");

        PrivateKey privateKey = cached.privateKey();
        PublicKey publicKey = algorithm.getPublicKeyDecoder().apply(stored.publicKey());

        assertPrivateKeyClass(algorithm, privateKey);
        assertPublicKeyClass(algorithm, publicKey);
        assertSignatureVerifies(algorithm, privateKey, publicKey);

        List<KeyHeader> published = run(() -> keys.listPublished());

        assertEquals(1, published.size());
        assertEquals(kid, published.getFirst().kid());
        assertEquals(algorithm, published.getFirst().alg());
        assertArrayEquals(stored.publicKey(), published.getFirst().publicKey());

        JWKSet jwks = run(() -> jwksBuilder.getJwks());

        assertEquals(1, jwks.getKeys().size());
        assertJwk(algorithm, jwks.getKeys().getFirst(), kid, publicKey);
    }

    // --- assertions ---

    private static void assertPrivateKeyClass(Algorithm algorithm, PrivateKey key) {
        if (isRsa(algorithm)) {
            assertInstanceOf(RSAPrivateKey.class, key);
            assertEquals("RSA", key.getAlgorithm());
        } else {
            assertInstanceOf(ECPrivateKey.class, key);
            assertEquals("EC", key.getAlgorithm());
        }
    }

    private static void assertPublicKeyClass(Algorithm algorithm, PublicKey key) {
        if (isRsa(algorithm)) {
            assertInstanceOf(RSAPublicKey.class, key);
            assertEquals("RSA", key.getAlgorithm());
        } else {
            assertInstanceOf(ECPublicKey.class, key);
            assertEquals("EC", key.getAlgorithm());
        }
    }

    private static void assertSignatureVerifies(
            Algorithm algorithm,
            PrivateKey privateKey,
            PublicKey publicKey) throws GeneralSecurityException {
        byte[] payload = ("bootstrap-" + algorithm.name()).getBytes(StandardCharsets.UTF_8);

        Signature signer = Signature.getInstance(signatureAlgorithm(algorithm));
        configurePss(signer, algorithm);
        signer.initSign(privateKey);
        signer.update(payload);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(signatureAlgorithm(algorithm));
        configurePss(verifier, algorithm);
        verifier.initVerify(publicKey);
        verifier.update(payload);

        assertTrue(verifier.verify(signature),
                () -> "подпись " + algorithm + " не проверяется соответствующим публичным ключом");
    }

    private static void assertJwk(
            Algorithm algorithm,
            JWK jwk,
            String kid,
            PublicKey publicKey) {
        assertEquals(kid, jwk.getKeyID());
        assertNotNull(jwk.getAlgorithm());
        assertEquals(algorithm.name(), jwk.getAlgorithm().getName());
        assertFalse(jwk.isPrivate());

        if (isRsa(algorithm)) {
            RSAKey rsa = assertInstanceOf(RSAKey.class, jwk);
            RSAPublicKey expected = assertInstanceOf(RSAPublicKey.class, publicKey);

            assertEquals("RSA", rsa.getKeyType().getValue());
            assertEquals(expected.getModulus(), rsa.getModulus().decodeToBigInteger());
            assertEquals(expected.getPublicExponent(), rsa.getPublicExponent().decodeToBigInteger());
        } else {
            ECKey ec = assertInstanceOf(ECKey.class, jwk);
            ECPublicKey expected = assertInstanceOf(ECPublicKey.class, publicKey);

            assertEquals("EC", ec.getKeyType().getValue());
            assertEquals(EcKeyCodec.jwkX(expected), ec.getX().toString());
            assertEquals(EcKeyCodec.jwkY(expected), ec.getY().toString());
            assertEquals(curveName(algorithm), ec.getCurve().getName());
        }
    }

    // --- algorithm mapping ---

    private static boolean isRsa(Algorithm algorithm) {
        return algorithm.name().startsWith("RS") || algorithm.name().startsWith("PS");
    }

    private static String signatureAlgorithm(Algorithm algorithm) {
        return switch (algorithm) {
            case RS256 -> "SHA256withRSA";
            case RS384 -> "SHA384withRSA";
            case RS512 -> "SHA512withRSA";
            case PS256, PS384, PS512 -> "RSASSA-PSS";
            case ES256 -> "SHA256withECDSA";
            case ES384 -> "SHA384withECDSA";
            case ES512 -> "SHA512withECDSA";
        };
    }

    private static void configurePss(Signature signature, Algorithm algorithm)
            throws GeneralSecurityException {
        if (!algorithm.name().startsWith("PS")) {
            return;
        }

        String digest = switch (algorithm) {
            case PS256 -> "SHA-256";
            case PS384 -> "SHA-384";
            case PS512 -> "SHA-512";
            default -> throw new IllegalArgumentException("Not a PSS algorithm: " + algorithm);
        };

        int saltLength = switch (algorithm) {
            case PS256 -> 32;
            case PS384 -> 48;
            case PS512 -> 64;
            default -> throw new IllegalArgumentException("Not a PSS algorithm: " + algorithm);
        };

        signature.setParameter(new PSSParameterSpec(
                digest,
                "MGF1",
                new MGF1ParameterSpec(digest),
                saltLength,
                1));
    }

    private static String curveName(Algorithm algorithm) {
        return switch (algorithm) {
            case ES256 -> "P-256";
            case ES384 -> "P-384";
            case ES512 -> "P-521";
            default -> throw new IllegalArgumentException("Not an EC algorithm: " + algorithm);
        };
    }

    // --- helpers ---

    private String singleKeyKid() {
        return pool.query("SELECT kid FROM keymaster.signing_key")
                .execute()
                .map(rows -> rows.iterator().next().getString("kid"))
                .await().atMost(TIMEOUT);
    }

    private static <T> T run(Supplier<Uni<T>> supplier) throws Throwable {
        return VertxContextSupport.subscribeAndAwait(() -> supplier.get()
                .ifNoItem()
                .after(OP_TIMEOUT)
                .fail());
    }
}
