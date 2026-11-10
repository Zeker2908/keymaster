package ru.zeker.keymaster.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepositoryBase;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.domain.key.KeyHeader;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class SigningKeyRepository implements PanacheRepositoryBase<SigningKey, String> {

    public Uni<List<KeyHeader>> listPublishedCandidates(Instant now) {
        return getSession()
                .chain(session -> session.createQuery("""
                                SELECT new ru.zeker.keymaster.domain.key.KeyHeader(
                                    k.kid,
                                    k.alg,
                                    k.publicKey,
                                    k.timeline.publishAt,
                                    k.timeline.activateAt,
                                    k.timeline.retireAt,
                                    k.timeline.removeAt,
                                    k.timeline.revokedAt
                                )
                                FROM SigningKey k
                                WHERE k.timeline.publishAt <= :now
                                  AND (k.timeline.revokedAt IS NULL OR k.timeline.revokedAt > :now)
                                  AND (k.timeline.removeAt IS NULL OR k.timeline.removeAt > :now)
                                """, KeyHeader.class)
                        .setParameter("now", now)
                        .getResultList());
    }

    public Uni<SigningKey> findByKid(String kid) {
        return find("kid = ?1", kid)
                .firstResult();
    }

    public Uni<Boolean> existsAny() {
        return count().map(count -> count > 0);
    }

    public Uni<SigningKey> create(SigningKey key) {
        return PersistenceErrors.translate(persistAndFlush(key));
    }
}
