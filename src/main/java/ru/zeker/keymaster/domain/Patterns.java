package ru.zeker.keymaster.domain;

public final class Patterns {

    public static final String UUID = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$";
    public static final String ROLE_NAME = "^[a-z0-9][a-z0-9._:-]{0,63}$";
    public static final String LOGIN = "^[a-z0-9._-]+$";

    public static final String TIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";

    private Patterns() {
    }
}
