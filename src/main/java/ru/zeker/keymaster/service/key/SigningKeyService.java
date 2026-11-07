package ru.zeker.keymaster.service.key;

import io.quarkus.hibernate.reactive.panache.Panache;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.domain.AuditAction;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.domain.key.GeneratedKey;
import ru.zeker.keymaster.domain.key.KeyLifecycle;
import ru.zeker.keymaster.domain.key.KeyTimeline;
import ru.zeker.keymaster.mapper.SigningKeyMapper;
import ru.zeker.keymaster.repository.SigningKeyRepository;
import ru.zeker.keymaster.service.AuditService;
import ru.zeker.keymaster.util.AuditDetails;
import ru.zeker.keymaster.util.Secrets;

import java.time.Clock;
import java.util.Map;

@Slf4j
@ApplicationScoped
@RequiredArgsConstructor
public class SigningKeyService {

    private final SigningKeyRepository signingKeys;
    private final AuditService audits;
    private final KeyCipher cipher;
    private final SigningKeyGenerator generator;
    private final KeyLifecycle lifecycle;
    private final SigningKeyMapper mapper;
    private final Clock clock;

    public Uni<Void> createKey() {
        log.info("Starting signing key creation");

        KeyTimeline timeline = KeyTimeline.initial(clock.instant());
        lifecycle.validate(timeline, true);

        log.debug("Signing key timeline validated: publishAt={}, activateAt={}",
                timeline.publishAt(), timeline.activateAt());

        return generator.generate()
                .invoke(key -> log.debug("Signing key pair generated, kid={}", key.kid()))
                .map(this::encryptKeyPair)
                .map(pair -> mapper.toRsaEntity(pair, timeline))
                .chain(key -> Panache.withTransaction(() -> persistKey(key)))
                .invoke(() -> log.info("Signing key creation completed successfully"))
                .onFailure().invoke(e -> log.error("Signing key creation failed: {}", e.getMessage()));
    }

    private Uni<Void> persistKey(SigningKey key) {
        return signingKeys.create(key)
                .invoke(sk -> log.info("Signing key {} successfully saved", sk.getKid()))
                .call(sk -> audits.recordKey(AuditAction.ROLE_CREATED, sk, AuditDetails.keyCreated(sk)))
                .onFailure().invoke(e -> log.error("Failed to persist signing key {} : {}", key.getKid(), e.getMessage()))
                .replaceWithVoid();
    }

    private Map.Entry<EncryptedKey, GeneratedKey> encryptKeyPair(GeneratedKey generatedKey) {
        try {
            EncryptedKey encryptedKey = cipher.encrypt(generatedKey.privatePkcs8(), generatedKey.kid());
            log.debug("Private key encrypted successfully, kid={}", generatedKey.kid());
            return Map.entry(encryptedKey, generatedKey);
        } catch (Exception e) {
            log.error("Failed to encrypt private key, kid={}", generatedKey.kid());
            throw e;
        } finally {
            Secrets.wipe(generatedKey.privatePkcs8());
        }
    }
}
