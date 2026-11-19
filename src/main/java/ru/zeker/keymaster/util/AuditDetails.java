package ru.zeker.keymaster.util;

import ru.zeker.keymaster.domain.entity.Role;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.domain.key.KeyTimeline;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class AuditDetails {

    private AuditDetails() {
    }

    public static Map<String, Object> userCreated(String login, Collection<Role> roles) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("login", login);
        details.put("roles", roles == null ? List.of() : roles.stream().map(Role::getName).toList());
        return details;
    }

    public static Map<String, Object> roleAssigned(Role role) {
        return Map.of("role", role.getName());
    }

    public static Map<String, Object> roleRevoked(Role role) {
        return Map.of("role", role.getName());
    }

    public static Map<String, Object> keyCreated(SigningKey key) {
        KeyTimeline timeline = key.getTimeline();
        return Map.of(
                "kid", key.getKid(),
                "alg", key.getAlg(),
                "publishAt", timeline.publishAt(),
                "activateAt", timeline.activateAt()
        );
    }
}
