package ru.zeker.keymaster.domain;

import jakarta.enterprise.context.RequestScoped;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@RequestScoped
public class UserContext {
    private UUID userId;
}