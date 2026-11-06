package ru.zeker.keymaster.util;

import org.apache.commons.lang3.CharUtils;

import java.nio.CharBuffer;
import java.text.Normalizer;
import java.util.Arrays;

public final class Secrets {

    private Secrets() {
    }

    public static void wipe(char[] secret) {
        if (secret != null) Arrays.fill(secret, CharUtils.NUL);
    }

    public static void wipe(byte[] secret) {
        if (secret != null) Arrays.fill(secret, (byte) 0);
    }

    /**
     * Normalizes the password using NFKC.
     * Returns the original array if no normalization is needed.
     * Wipes the original array if a new one is created.
     */
    public static char[] normalize(char[] raw) {
        CharBuffer view = CharBuffer.wrap(raw);
        if (Normalizer.isNormalized(view, Normalizer.Form.NFKC)) {
            return raw;
        }
        try {
            return Normalizer.normalize(view, Normalizer.Form.NFKC).toCharArray();
        } finally {
            wipe(raw);
        }
    }
}
