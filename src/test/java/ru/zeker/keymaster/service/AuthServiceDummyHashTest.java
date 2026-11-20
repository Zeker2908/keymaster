package ru.zeker.keymaster.service;

import io.quarkus.arc.ClientProxy;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.config.PasswordConfig;
import ru.zeker.keymaster.service.password.PasswordHasher;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AuthServiceDummyHashTest {

    @Inject
    AuthService authService;

    @Inject
    PasswordHasher hasher;

    @Inject
    PasswordConfig config;

    @Test
    void dummyHashIsComputedWithTheSameArgon2ParametersAsRealHashes() throws Exception {
        AuthService actual = ClientProxy.unwrap(authService);

        Field field = AuthService.class.getDeclaredField("dummyHash");
        field.setAccessible(true);
        String dummyHash = (String) field.get(actual);

        String realHash = hasher.hash("Password123!Abcde".toCharArray())
                .await().indefinitely();

        assertNotNull(dummyHash);
        assertTrue(dummyHash.startsWith("$argon2id$"));

        Map<String, String> dummyParameters = argon2Parameters(dummyHash);

        assertEquals(argon2Parameters(realHash), dummyParameters);
        assertEquals(Integer.toString(config.argon2().memory()), dummyParameters.get("m"));
        assertEquals(Integer.toString(config.argon2().iterations()), dummyParameters.get("t"));
        assertEquals(Integer.toString(config.argon2().parallelism()), dummyParameters.get("p"));
    }

    private static Map<String, String> argon2Parameters(String hash) {
        String[] parts = hash.split("\\$");

        return Arrays.stream(parts[3].split(","))
                .map(parameter -> parameter.split("=", 2))
                .collect(Collectors.toMap(parameter -> parameter[0], parameter -> parameter[1]));
    }
}
