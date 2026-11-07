package ru.zeker.keymaster.service;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.AuditAction;
import ru.zeker.keymaster.domain.context.Actor;
import ru.zeker.keymaster.domain.entity.AuditLog;
import ru.zeker.keymaster.domain.entity.Principal;
import ru.zeker.keymaster.domain.entity.Role;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.repository.AuditRepository;

import java.util.Map;

@ApplicationScoped
@RequiredArgsConstructor
public class AuditService {

    private static final String USER = "user";
    private static final String ROLE = "role";
    private static final String KEY = "signingKey";

    private final AuditRepository audits;
    private final ObjectMapper mapper;

    public Uni<Void> recordUser(Actor actor, AuditAction action, Principal principal, Map<String, ?> details) {
        return record(actor, action, USER, principal.getId().toString(), details);
    }

    public Uni<Void> recordRole(Actor actor, AuditAction action, Role role) {
        return record(actor, action, ROLE, role.getId().toString(), Map.of());
    }

    public Uni<Void> recordKey(AuditAction action, SigningKey signingKey, Map<String, ?> details) {
        return record(null, action, KEY, signingKey.getKid(), details);
    }

    public Uni<Void> record(Actor actor, AuditAction action, String targetType,
                            String targetId, Map<String, ?> details) {
        AuditLog e = AuditLog.builder()
                .actorId(actor != null ? actor.userId() : null)
                .action(action.code())
                .targetType(targetType)
                .targetId(targetId)
                .details(mapper.valueToTree(details))
                .requestId(actor != null ? actor.requestId() : null)
                .build();
        return audits.persist(e).replaceWithVoid();
    }
}