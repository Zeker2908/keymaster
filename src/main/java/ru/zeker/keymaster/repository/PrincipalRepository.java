package ru.zeker.keymaster.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepositoryBase;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.entity.Principal;

import java.util.UUID;

@ApplicationScoped
public class PrincipalRepository implements PanacheRepositoryBase<Principal, UUID> {

    public Uni<Principal> findById(UUID id) {
        return find("id = ?1", id).firstResult();
    }
}
