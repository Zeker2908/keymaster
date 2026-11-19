package ru.zeker.keymaster.domain;

import java.util.Base64;

public final class Consts {

    public static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    public static final String SHA_256 = "SHA-256";

    private Consts() {
    }
}
