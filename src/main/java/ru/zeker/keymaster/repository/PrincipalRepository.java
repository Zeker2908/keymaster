package ru.zeker.keymaster.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepositoryBase;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.entity.Principal;
import ru.zeker.keymaster.domain.jwt.Subject;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@ApplicationScoped
public class PrincipalRepository implements PanacheRepositoryBase<Principal, UUID> {

    public Uni<Principal> create(Principal principal) {
        return PersistenceErrors.translate(persistAndFlush(principal));
    }

    public Uni<Principal> findById(UUID id) {
        return find("id = ?1", id).firstResult();
    }

    public Uni<Subject> findSubjectByLogin(String login) {
        String sql = """
                SELECT p.id,
                       c.secret_hash,
                       COALESCE(
                           (SELECT string_agg(r.name, ',' ORDER BY r.name)
                            FROM {h-schema}principal_role pr
                            JOIN {h-schema}role r ON r.id = pr.role_id
                            WHERE pr.principal_id = p.id),
                           ''
                       ) AS roles
                FROM {h-schema}principal p
                JOIN {h-schema}credential c ON c.principal_id = p.id
                WHERE p.login = :login
                  AND p.kind = 'USER'
                  AND p.status = 'ACTIVE'
                """;

        return getSession()
                .chain(session -> session.createNativeQuery(sql, Object[].class)
                        .setParameter("login", login)
                        .getSingleResultOrNull())
                .map(row -> row == null ? null : new Subject(
                        (UUID) row[0],
                        (String) row[1],
                        ((String) row[2]).isBlank()
                                ? List.of()
                                : Arrays.asList(((String) row[2]).split(","))
                ));
    }
}
