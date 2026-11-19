package ru.zeker.keymaster.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import ru.zeker.keymaster.domain.Algorithm;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.domain.key.EncryptedKey;
import ru.zeker.keymaster.domain.key.GeneratedKey;
import ru.zeker.keymaster.domain.key.KeyTimeline;

import java.util.Map;

@Mapper
public interface SigningKeyMapper {

    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "kid", source = "keyPair.value.kid")
    @Mapping(target = "alg", source = "algorithm")
    @Mapping(target = "publicKey", source = "keyPair.value.publicSpki")
    @Mapping(target = "privateKeyEnc", source = "keyPair.key.ciphertext")
    @Mapping(target = "nonce", source = "keyPair.key.nonce")
    @Mapping(target = "masterKeyVersion", source = "keyPair.key.masterKeyVersion")
    SigningKey toEntity(Map.Entry<EncryptedKey, GeneratedKey> keyPair,
                        KeyTimeline timeline,
                        Algorithm algorithm);
}
