package ru.zeker.keymaster.domain.context;

import jakarta.enterprise.context.RequestScoped;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@RequestScoped
public class RequestContext {
    private String requestId;
    private UUID userId;

    public Actor actor() {
        return new Actor(userId, requestId);
    }
}
