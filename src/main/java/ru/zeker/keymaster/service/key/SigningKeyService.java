package ru.zeker.keymaster.service.key;

import io.quarkus.hibernate.reactive.panache.Panache;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.AuditAction;
import ru.zeker.keymaster.domain.context.Actor;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.domain.key.GeneratedKey;
import ru.zeker.keymaster.domain.key.KeyHeader;
import ru.zeker.keymaster.domain.key.KeyLifecycle;
import ru.zeker.keymaster.domain.key.KeyTimeline;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;
import ru.zeker.keymaster.mapper.SigningKeyMapper;
import ru.zeker.keymaster.repository.SigningKeyRepository;
import ru.zeker.keymaster.service.AuditService;
import ru.zeker.keymaster.util.AuditDetails;
import ru.zeker.keymaster.util.Secrets;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
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

    public Uni<Boolean> ensureInitialKey(Algorithm algorithm) {
        return Panache.withSession(signingKeys::existsAny)
                .chain(exists -> exists
                        ? Uni.createFrom().item(false)
                        : createKey(Actor.SYSTEM, KeyTimeline.initial(clock.instant()), algorithm, true)
                        .replaceWith(true))
                .onFailure(this::isScheduleConflict)
                .recoverWithUni(this::recheckAfterScheduleConflict);
    }

    public Uni<Void> createKey(Actor actor, Algorithm algorithm) {
        return createKey(actor, KeyTimeline.initial(clock.instant()), algorithm, true);
    }

    public Uni<Void> createKey(Actor actor, KeyTimeline timeline, Algorithm algorithm) {
        return createKey(actor, timeline, algorithm, false);
    }

    public Uni<List<KeyHeader>> listPublished() {
        Instant now = clock.instant();

        return Panache.withSession(() -> signingKeys.listPublishedCandidates(now))
                .map(candidates -> {
                    List<KeyHeader> published = candidates.stream()
                            .filter(key -> lifecycle.isPublished(
                                    lifecycle.stateAt(key.timeline(), now)))
                            .toList();

                    log.debug(
                            "Found {} published signing keys out of {} candidates",
                            published.size(),
                            candidates.size()
                    );

                    return published;
                });
    }

    private Uni<Void> createKey(Actor actor, KeyTimeline timeline, Algorithm algorithm, boolean initialKey) {
        log.info("Starting signing key creation");

        lifecycle.validate(timeline, initialKey);

        log.debug("Signing key timeline validated: publishAt={}, activateAt={}",
                timeline.publishAt(), timeline.activateAt());

        return generator.generate(algorithm)
                .invoke(key -> log.debug("Signing key pair generated, kid={}", key.kid()))
                .map(this::encryptKeyPair)
                .map(pair -> mapper.toEntity(pair, timeline, algorithm))
                .chain(key -> Panache.withTransaction(() -> persistKey(actor, key)))
                .invoke(() -> log.info("Signing key creation completed successfully"))
                .onFailure(e -> !(initialKey && isScheduleConflict(e)))
                .invoke(e -> log.error("Signing key creation failed: {}", e.getMessage()));
    }

    private Uni<Boolean> recheckAfterScheduleConflict(Throwable failure) {
        log.debug("Initial signing key creation conflicted with another instance; re-checking key presence");

        return Panache.withSession(signingKeys::existsAny)
                .chain(exists -> exists
                        ? Uni.createFrom().item(false)
                        : Uni.createFrom().failure(new IllegalStateException(
                        "Initial signing key creation failed: another instance won the race, "
                                + "but no signing key exists. Check the database and master key configuration.",
                        failure)));
    }

    private boolean isScheduleConflict(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof KeyMasterException exception
                    && exception.getCode() == ErrorCode.KEY_SCHEDULE_CONFLICT) {
                return true;
            }
        }

        return false;
    }

    private Uni<Void> persistKey(Actor actor, SigningKey key) {
        return signingKeys.create(key)
                .invoke(sk -> log.info("Signing key {} successfully saved", sk.getKid()))
                .call(sk -> audits.recordKey(actor, AuditAction.KEY_CREATED, sk, AuditDetails.keyCreated(sk)))
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
