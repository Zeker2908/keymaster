package ru.zeker.keymaster.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.entity.Principal;

import java.util.UUID;

@ApplicationScoped
public class PrincipalRepository implements PanacheRepositoryBase<Principal, UUID> {
}
