package ru.zeker.keymaster.service.key;

import io.quarkus.cache.Cache;
import io.quarkus.cache.CacheName;
import io.quarkus.hibernate.reactive.panache.Panache;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.domain.key.SigningKeyData;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.repository.SigningKeyRepository;
import ru.zeker.keymaster.util.Secrets;

@Slf4j
@ApplicationScoped
public class SigningKeyCache {

    private final SigningKeyRepository signingKeys;
    private final Cache cache;
    private final KeyCipher cipher;

    public SigningKeyCache(SigningKeyRepository signingKeys,
                           @CacheName("keys") Cache cache,
                           KeyCipher cipher) {
        this.signingKeys = signingKeys;
        this.cache = cache;
        this.cipher = cipher;
    }

    public Uni<SigningKeyData> get(String kid) {
        return cache.getAsync(kid, this::loadSigningKey);
    }

    public Uni<Void> invalidate(String kid) {
        return cache.invalidate(kid)
                .invoke(() -> log.debug("Signing key cache invalidated: kid={}", kid));
    }

    public Uni<Void> invalidateAll() {
        return cache.invalidateAll()
                .invoke(() -> log.info("Signing key cache cleared"));
    }

    private Uni<SigningKeyData> loadSigningKey(String kid) {
        log.debug("Loading signing key from database: kid={}", kid);

        return Panache.withSession(() -> signingKeys.findByKid(kid))
                .onItem().ifNull().failWith(() -> new KeyMasterException(ErrorCode.KEY_NOT_FOUND))
                .map(this::decryptSigningKey)
                .onFailure().invoke(error ->
                        log.error("Failed to load signing key: kid={}", kid, error)
                );
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
