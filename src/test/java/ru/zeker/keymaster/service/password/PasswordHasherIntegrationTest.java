package ru.zeker.keymaster.service.password;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class PasswordHasherIntegrationTest {

    @Inject
    PasswordHasher hasher;

    @Test
    void shouldHashPasswordWithArgon2id() {
        String hash = hasher.hash("Password123!Abcde".toCharArray())
                .await().indefinitely();

        assertTrue(hash.startsWith("$argon2id$"));
    }

    @Test
    void shouldGenerateDifferentHashesForSamePassword() {
        String first = hasher.hash("Password123!Abcde".toCharArray())
                .await().indefinitely();

        String second = hasher.hash("Password123!Abcde".toCharArray())
                .await().indefinitely();

        assertNotEquals(first, second);
    }

    @Test
    void shouldVerifyCorrectPassword() {
        String hash = hasher.hash("Password123!Abcde".toCharArray())
                .await().indefinitely();

        assertTrue(hasher.verify(hash, "Password123!Abcde".toCharArray())
                .await().indefinitely());

        assertFalse(hasher.verify(hash, "WrongPassword123!".toCharArray())
                .await().indefinitely());
    }
}
