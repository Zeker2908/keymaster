package ru.zeker.keymaster.config.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Base64;

public class MasterKeyValidator implements ConstraintValidator<ValidMasterKey, String> {

    private static final int MASTER_KEY_SIZE = 32;

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) {
            return true;
        }

        try {
            return Base64.getDecoder().decode(value).length == MASTER_KEY_SIZE;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
