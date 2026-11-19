package ru.zeker.keymaster.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepositoryBase;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import ru.zeker.keymaster.domain.entity.Role;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

@ApplicationScoped
public class RoleRepository implements PanacheRepositoryBase<Role, UUID> {

    public Uni<Role> create(Role role) {
        return PersistenceErrors.translate(persistAndFlush(role));
    }

    public Uni<Role> findByName(String name) {
        return find("name = ?1", name).firstResult();
    }

    public Uni<Role> lockByName(String name) {
        return find("name = ?1", name)
                .withLock(LockModeType.PESSIMISTIC_WRITE)
                .firstResult();
    }

    public Uni<List<Role>> findByNameIn(Collection<String> names) {
        if (names == null || names.isEmpty()) {
            return Uni.createFrom().item(List::of);
        }
        return find("name in ?1", List.copyOf(names)).list();
    }
}
