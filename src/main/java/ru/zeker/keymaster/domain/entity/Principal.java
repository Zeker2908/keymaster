package ru.zeker.keymaster.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import ru.zeker.keymaster.domain.PrincipalKind;
import ru.zeker.keymaster.domain.PrincipalStatus;

@Getter
@Setter
@Entity
@Table(name = "principals")
public class Principal extends BaseEntity {

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PrincipalKind kind;

    @Column(nullable = false, unique = true, length = 32)
    private String login;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PrincipalStatus status;
}