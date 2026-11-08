package ru.zeker.keymaster.domain.key;

public record GeneratedKey(
        String kid,
        byte[] publicSpki,
        byte[] privatePkcs8
) {
    public GeneratedKey {
        publicSpki = publicSpki.clone();
        privatePkcs8 = privatePkcs8.clone();
    }
}
