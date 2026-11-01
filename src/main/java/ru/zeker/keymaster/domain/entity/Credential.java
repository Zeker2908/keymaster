package ru.zeker.keymaster.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@Entity
@Table(name = "credentials")
public class Credential {

    @Id
    private UUID principalId;

    @MapsId
    @OneToOne(optional = false)
    @JoinColumn(name = "principal_id")
    private Principal principal;

    @Column(name = "secret_hash", nullable = false)
    private String secretHash;

    @UpdateTimestamp
    @Column(name = "changed_at", nullable = false)
    private Instant changedAt;
}
