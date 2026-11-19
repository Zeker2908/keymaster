package ru.zeker.keymaster.util;

import org.apache.commons.lang3.CharUtils;
import ru.zeker.keymaster.domain.Consts;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.HexFormat;

public final class Secrets {

    private Secrets() {
    }

    public static void wipe(char[] secret) {
        if (secret != null) Arrays.fill(secret, CharUtils.NUL);
    }

    public static void wipe(byte[] secret) {
        if (secret != null) Arrays.fill(secret, (byte) 0);
    }

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

    public static String normalize(String raw) {
        if (Normalizer.isNormalized(raw, Normalizer.Form.NFKC)) {
            return raw;
        }
        return Normalizer.normalize(raw, Normalizer.Form.NFKC);
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance(Consts.SHA_256).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    public static String hash(String raw) {
        byte[] digest = sha256(raw.trim().getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }
}
