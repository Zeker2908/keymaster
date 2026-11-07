package ru.zeker.keymaster.bootstrap;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

public class BootstrapSigningKeyTestProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "keymaster.bootstrap.signing-key.enabled", "true"
        );
    }
}
