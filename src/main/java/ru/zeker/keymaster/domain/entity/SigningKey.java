package ru.zeker.keymaster.domain.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.domain.key.KeyTimeline;

import java.time.Instant;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "signing_key")
public class SigningKey {

    public static final String KEY_SCHEDULE_EXCL = "signing_key_single_signer";

    @Id
    @Column(nullable = false, updatable = false)
    private String kid;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Algorithm alg;

    @Column(name = "public_key", nullable = false)
    private byte[] publicKey;

    @Getter(AccessLevel.NONE)
    @Column(name = "private_key_enc", nullable = false)
    private byte[] privateKeyEnc;

    @Getter(AccessLevel.NONE)
    @Column(nullable = false)
    private byte[] nonce;

    @Builder.Default
    @Getter(AccessLevel.NONE)
    @Column(name = "master_key_version", nullable = false)
    private short masterKeyVersion = 1;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Embedded
    private KeyTimeline timeline;

    public EncryptedKey encryptedKey() {
        return new EncryptedKey(privateKeyEnc.clone(), nonce.clone(), masterKeyVersion);
    }

}
