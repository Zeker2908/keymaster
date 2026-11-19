package ru.zeker.keymaster.repository;

import io.quarkus.hibernate.reactive.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import ru.zeker.keymaster.domain.entity.Credential;

import java.util.UUID;

@ApplicationScoped
public class CredentialRepository implements PanacheRepositoryBase<Credential, UUID> {
}
