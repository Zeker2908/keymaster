package ru.zeker.keymaster.domain.key;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public record EncryptedKey(
        byte[] ciphertext,
        byte[] nonce,
        short masterKeyVersion
) {
    public EncryptedKey {
        ciphertext = ciphertext.clone();
        nonce = nonce.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public byte[] nonce() {
        return nonce.clone();
    }
}
