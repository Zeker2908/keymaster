package ru.zeker.keymaster.config;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@QuarkusTest
class KeymasterConfigTest {

    @Inject
    KeymasterConfig config;

    @Test
    void toStringDoesNotExposeMasterKey() {
        String masterKey = config.keys().masterKey();
        assertNotNull(masterKey);

        assertDoesNotContainSecrets(config.toString(), masterKey);
        assertDoesNotContainSecrets(config.keys().toString(), masterKey);
    }

    private static void assertDoesNotContainSecrets(String text, String... secrets) {
        assertNotNull(text);

        for (String secret : secrets) {
            assertFalse(text.contains(secret),
                    () -> "secret leaked into config toString(): " + text);
        }
    }
}
