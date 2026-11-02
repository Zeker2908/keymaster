package ru.zeker.keymaster.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapsId;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "principal_roles")
public class PrincipalRole {

    public static final String PRIMARY_KEY = "principal_roles_pkey";

    @EmbeddedId
    private PrincipalRoleId id;

    @MapsId("principalId")
    @ManyToOne(optional = false)
    @JoinColumn(name = "principal_id", nullable = false)
    private Principal principal;

    @MapsId("roleId")
    @ManyToOne(optional = false)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @CreationTimestamp
    @Column(name = "assigned_at", nullable = false)
    private Instant assignedAt;
}
