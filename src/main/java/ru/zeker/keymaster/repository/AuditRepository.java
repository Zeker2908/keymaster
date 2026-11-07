package ru.zeker.keymaster.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.entity.AuditLog;

@ApplicationScoped
public class AuditRepository implements PanacheRepositoryBase<AuditLog, Long> {
}
