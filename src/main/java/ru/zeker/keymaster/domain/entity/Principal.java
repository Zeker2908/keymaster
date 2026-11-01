package ru.zeker.keymaster.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import ru.zeker.keymaster.domain.PrincipalKind;
import ru.zeker.keymaster.domain.PrincipalStatus;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "principals",
        uniqueConstraints = @UniqueConstraint(name = Principal.LOGIN_UQ, columnNames = "login"))
public class Principal extends BaseEntity {

    public static final String LOGIN_UQ = "principals_login_uq";

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PrincipalKind kind;

    @Column(nullable = false, unique = true, length = 32)
    private String login;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PrincipalStatus status;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;
}
