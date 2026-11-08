package ru.zeker.keymaster.service.key;

import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.config.KeymasterConfig;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.domain.key.GeneratedKey;
import ru.zeker.keymaster.exception.KeyDecryptionException;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KeyCipherTest {

    private static final String KID = "test-kid";
    private static final int MASTER_KEY_SIZE = 32;

    private static final String MASTER_KEY = base64Key((byte) 0x11);
    private static final String OTHER_MASTER_KEY = base64Key((byte) 0x22);

    @Test
    void encryptAndDecryptRoundTrip() {
        KeyCipher cipher = cipher(MASTER_KEY);
        byte[] plaintext = "private-key-material".getBytes(StandardCharsets.UTF_8);

        EncryptedKey encrypted = cipher.encrypt(plaintext, KID);

        assertArrayEquals(plaintext, cipher.decrypt(encrypted, KID));
        assertEquals(1, encrypted.masterKeyVersion());
    }

    @Test
    void decryptWithForeignMasterKeyFails() {
        KeyCipher encryptingCipher = cipher(MASTER_KEY);
        KeyCipher foreignCipher = cipher(OTHER_MASTER_KEY);

        EncryptedKey encrypted = encryptingCipher.encrypt(plaintext(), KID);

        assertThrows(KeyDecryptionException.class,
                () -> foreignCipher.decrypt(encrypted, KID));
    }

    @Test
    void decryptWithModifiedCiphertextFails() {
        KeyCipher cipher = cipher(MASTER_KEY);
        EncryptedKey encrypted = cipher.encrypt(plaintext(), KID);

        byte[] modifiedCiphertext = encrypted.ciphertext();
        modifiedCiphertext[0] ^= 0x01;
        EncryptedKey tampered = new EncryptedKey(
                modifiedCiphertext,
                encrypted.nonce(),
                encrypted.masterKeyVersion()
        );

        assertThrows(KeyDecryptionException.class, () -> cipher.decrypt(tampered, KID));
    }

    @Test
    void decryptWithModifiedNonceFails() {
        KeyCipher cipher = cipher(MASTER_KEY);
        EncryptedKey encrypted = cipher.encrypt(plaintext(), KID);

        byte[] modifiedNonce = encrypted.nonce();
        modifiedNonce[0] ^= 0x01;
        EncryptedKey tampered = new EncryptedKey(
                encrypted.ciphertext(),
                modifiedNonce,
                encrypted.masterKeyVersion()
        );

        assertThrows(KeyDecryptionException.class, () -> cipher.decrypt(tampered, KID));
    }

    @Test
    void decryptWithSubstitutedKidFails() {
        KeyCipher cipher = cipher(MASTER_KEY);
        EncryptedKey encrypted = cipher.encrypt(plaintext(), KID);

        assertThrows(KeyDecryptionException.class,
                () -> cipher.decrypt(encrypted, "another-kid"));
    }

    @Test
    void tenThousandEncryptionsNeverRepeatNonce() {
        KeyCipher cipher = cipher(MASTER_KEY);
        byte[] plaintext = plaintext();
        int encryptions = 10_000;

        Set<String> nonces = new HashSet<>(encryptions * 2);
        for (int i = 0; i < encryptions; i++) {
            EncryptedKey encrypted = cipher.encrypt(plaintext, KID);
            String nonce = Base64.getEncoder().encodeToString(encrypted.nonce());

            assertTrue(nonces.add(nonce), () -> "nonce repeated after " + nonces.size() + " encryptions");
        }

        assertEquals(encryptions, nonces.size());
    }

    @Test
    void invalidMasterKeyFailsConstruction() {
        assertThrows(IllegalStateException.class, () -> cipher("not base64"));
        assertThrows(IllegalStateException.class, () -> cipher(""));
        assertThrows(IllegalStateException.class, () -> cipher(base64(new byte[MASTER_KEY_SIZE - 1])));
        assertThrows(IllegalStateException.class, () -> cipher(base64(new byte[MASTER_KEY_SIZE + 1])));
    }

    @Test
    void secretsDoNotLeakIntoToStringExceptionsOrLogs() {
        KeyCipher cipher = cipher(MASTER_KEY);
        byte[] plaintext = plaintext();
        EncryptedKey encrypted = cipher.encrypt(plaintext, KID);

        String ciphertextBase64 = Base64.getEncoder().encodeToString(encrypted.ciphertext());
        String nonceBase64 = Base64.getEncoder().encodeToString(encrypted.nonce());

        assertSafe(encrypted.toString(), MASTER_KEY, ciphertextBase64, nonceBase64);

        GeneratedKey generatedKey = new GeneratedKey(
                KID,
                plaintext.clone(),
                plaintext.clone()
        );
        assertSafe(generatedKey.toString(),
                MASTER_KEY,
                Base64.getEncoder().encodeToString(plaintext),
                hex(plaintext));

        Logger rootLogger = Logger.getLogger("");
        CapturingHandler logs = new CapturingHandler();
        rootLogger.addHandler(logs);
        try {
            KeyDecryptionException exception = assertThrows(KeyDecryptionException.class,
                    () -> cipher(OTHER_MASTER_KEY).decrypt(encrypted, KID));

            assertSafe(throwableText(exception),
                    MASTER_KEY,
                    OTHER_MASTER_KEY,
                    ciphertextBase64,
                    nonceBase64,
                    Base64.getEncoder().encodeToString(plaintext),
                    hex(plaintext));
        } finally {
            rootLogger.removeHandler(logs);
        }

        assertSafe(logs.text(),
                MASTER_KEY,
                OTHER_MASTER_KEY,
                ciphertextBase64,
                nonceBase64,
                Base64.getEncoder().encodeToString(plaintext),
                hex(plaintext));
    }

    private static KeyCipher cipher(String masterKey) {
        KeymasterConfig config = mock(KeymasterConfig.class, RETURNS_DEEP_STUBS);
        when(config.keys().masterKey()).thenReturn(masterKey);
        return new KeyCipher(config);
    }

    private static byte[] plaintext() {
        byte[] plaintext = new byte[256];
        Arrays.fill(plaintext, (byte) 0x5A);
        return plaintext;
    }

    private static String base64Key(byte fill) {
        byte[] key = new byte[MASTER_KEY_SIZE];
        Arrays.fill(key, fill);
        return base64(key);
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

    private static String throwableText(Throwable throwable) {
        StringBuilder result = new StringBuilder();
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            result.append(current).append('\n');
        }
        return result.toString();
    }

    private static void assertSafe(String text, String... secrets) {
        for (String secret : secrets) {
            assertFalse(text.contains(secret),
                    () -> "secret leaked into: " + text);
        }
    }

    private static final class CapturingHandler extends Handler implements AutoCloseable {

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
                messages.append(throwableText(record.getThrown())).append('\n');
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
