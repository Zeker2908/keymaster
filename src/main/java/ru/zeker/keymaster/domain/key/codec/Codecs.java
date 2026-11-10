package ru.zeker.keymaster.domain.key.codec;

import java.util.Base64;

final class Codecs {

    public static final Base64.Encoder BASE64_URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
    public static final String SHA_256 = "SHA-256";

    private Codecs() {
    }
}
