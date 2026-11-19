package ru.zeker.keymaster.config.validation;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MasterKeyValidatorTest {

    private final MasterKeyValidator validator = new MasterKeyValidator();

    @Test
    void acceptsBase64Encoded32ByteKey() {
        assertTrue(validator.isValid(base64(new byte[32]), null));
    }

    @Test
    void rejectsNullOrInvalidKeys() {
        assertTrue(validator.isValid(null, null));
        assertFalse(validator.isValid("not base64", null));
        assertFalse(validator.isValid("", null));
        assertFalse(validator.isValid(base64(new byte[31]), null));
        assertFalse(validator.isValid(base64(new byte[33]), null));
    }

    private static String base64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }
}
