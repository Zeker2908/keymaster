package ru.zeker.keymaster.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class LoginNormalizerTest {

    @Test
    void normalizesNfkcAndCase() {
        assertEquals("admin", LoginNormalizer.normalize("ＡＤＭＩＮ"));
        assertEquals("admin", LoginNormalizer.normalize("Admin"));
        assertEquals("admin", LoginNormalizer.normalize(" admin "));
    }

    @Test
    void rejectsBlankOrInvalidLogin() {
        assertNull(LoginNormalizer.normalize(null));
        assertNull(LoginNormalizer.normalize(""));
        assertNull(LoginNormalizer.normalize("   "));
        assertNull(LoginNormalizer.normalize("bad login"));
        assertNull(LoginNormalizer.normalize("a".repeat(LoginNormalizer.MAX_LENGTH + 1)));
    }
}
