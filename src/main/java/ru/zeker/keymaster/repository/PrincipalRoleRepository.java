package ru.zeker.keymaster.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.entity.PrincipalRole;
import ru.zeker.keymaster.domain.entity.PrincipalRoleId;

@ApplicationScoped
public class PrincipalRoleRepository implements PanacheRepositoryBase<PrincipalRole, PrincipalRoleId> {
}
