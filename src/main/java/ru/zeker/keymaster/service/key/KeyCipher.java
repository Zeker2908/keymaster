package ru.zeker.keymaster.service.key;

import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.config.KeymasterConfig;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.exception.KeyDecryptionException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

@ApplicationScoped
public final class KeyCipher {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final String KEY_ALGORITHM = "AES";

    private static final int KEY_SIZE = 32;
    private static final int NONCE_SIZE = 12;
    private static final int TAG_SIZE = 128;

    private static final short MASTER_KEY_VERSION = 1;

    private final byte[] masterKey;
    private final SecureRandom secureRandom = new SecureRandom();

    public KeyCipher(KeymasterConfig config) {

        try {
            this.masterKey = Base64.getDecoder().decode(config.keys().masterKey());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Master key must be valid Base64");
        }

        if (this.masterKey.length != KEY_SIZE) {
            throw new IllegalStateException("Master key must be 32 bytes");
        }
    }

    public EncryptedKey encrypt(byte[] plaintext, String kid) {
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(kid, "kid");

        byte[] nonce = new byte[NONCE_SIZE];
        secureRandom.nextBytes(nonce);

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);

            SecretKeySpec key = new SecretKeySpec(masterKey, KEY_ALGORITHM);
            GCMParameterSpec parameters = new GCMParameterSpec(TAG_SIZE, nonce);

            cipher.init(Cipher.ENCRYPT_MODE, key, parameters);
            cipher.updateAAD(kid.getBytes(StandardCharsets.UTF_8));

            byte[] ciphertext = cipher.doFinal(plaintext);

            return new EncryptedKey(ciphertext, nonce, MASTER_KEY_VERSION);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Key encryption failed");
        }
    }

    public byte[] decrypt(EncryptedKey encryptedKey, String kid) {
        Objects.requireNonNull(encryptedKey, "encryptedKey");
        Objects.requireNonNull(kid, "kid");

        try {

            //TODO: добавить поддержку полноценной ротации
            if (encryptedKey.masterKeyVersion() != MASTER_KEY_VERSION) {
                throw new GeneralSecurityException();
            }

            byte[] nonce = encryptedKey.nonce();

            if (nonce.length != NONCE_SIZE) {
                throw new GeneralSecurityException();
            }

            Cipher cipher = Cipher.getInstance(ALGORITHM);

            SecretKeySpec key = new SecretKeySpec(masterKey, KEY_ALGORITHM);
            GCMParameterSpec parameters = new GCMParameterSpec(TAG_SIZE, nonce);

            cipher.init(Cipher.DECRYPT_MODE, key, parameters);
            cipher.updateAAD(kid.getBytes(StandardCharsets.UTF_8));

            return cipher.doFinal(encryptedKey.ciphertext());
        } catch (Exception e) {
            throw new KeyDecryptionException(e);
        }
    }
}
