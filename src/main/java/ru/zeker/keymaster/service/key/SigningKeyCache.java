package ru.zeker.keymaster.service.key;

import io.quarkus.cache.Cache;
import io.quarkus.cache.CacheName;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.domain.key.SigningKeyData;
import ru.zeker.keymaster.util.Secrets;

@Slf4j
@ApplicationScoped
public class SigningKeyCache {

    private final Cache cache;
    private final KeyCipher cipher;

    public SigningKeyCache(@CacheName("keys") Cache cache,
                           KeyCipher cipher) {
        this.cache = cache;
        this.cipher = cipher;
    }

    public Uni<SigningKeyData> get(SigningKey key) {
        return cache.getAsync(key.getKid(), _ -> Uni.createFrom().item(key)
                .map(this::decryptSigningKey));
    }

    public Uni<Void> invalidate(String kid) {
        return cache.invalidate(kid)
                .invoke(() -> log.debug("Signing key cache invalidated: kid={}", kid));
    }

    public Uni<Void> invalidateAll() {
        return cache.invalidateAll()
                .invoke(() -> log.info("Signing key cache cleared"));
    }

    private SigningKeyData decryptSigningKey(SigningKey key) {
        Algorithm algorithm = key.getAlg();
        String kid = key.getKid();
        byte[] privateKeyBytes = cipher.decrypt(key.encryptedKey(), kid);
        try {
            return new SigningKeyData(
                    kid,
                    algorithm,
                    algorithm.getPrivateKeyDecoder().apply(privateKeyBytes)
            );
        } finally {
            Secrets.wipe(privateKeyBytes);
        }
    }
}
