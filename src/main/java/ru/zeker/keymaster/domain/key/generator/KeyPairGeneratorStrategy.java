package ru.zeker.keymaster.domain.key.generator;

import ru.zeker.keymaster.domain.key.GeneratedKey;

import java.security.GeneralSecurityException;

public interface KeyPairGeneratorStrategy {

    GeneratedKey generate() throws GeneralSecurityException;
}
