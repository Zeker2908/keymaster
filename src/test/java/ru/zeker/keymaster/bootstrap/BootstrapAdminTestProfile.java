package ru.zeker.keymaster.bootstrap;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

public class BootstrapAdminTestProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "keymaster.bootstrap.admin.enabled", "true",
                "keymaster.bootstrap.admin.login", "bootstrap-admin",
                "keymaster.bootstrap.admin.password", "StrongBootstrapPassword123!"
        );
    }
}
