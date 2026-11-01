package ru.zeker.keymaster.util;

import io.vertx.pgclient.PgException;
import org.hibernate.exception.ConstraintViolationException;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class UniqueViolations {

    private static final String UNIQUE_VIOLATION = "23505";
    private static final Pattern CONSTRAINT_IN_MESSAGE =
            Pattern.compile("unique constraint \"([^\"]+)\"");

    private UniqueViolations() {}

    public static Optional<String> constraintName(Throwable failure) {
        boolean unique = false;
        String name = null;

        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof PgException pg) {
                unique |= UNIQUE_VIOLATION.equals(pg.getSqlState());
                if (name == null) {
                    name = pg.getConstraint();
                }
            }
            if (cause instanceof ConstraintViolationException violation) {
                unique |= UNIQUE_VIOLATION.equals(violation.getSQLState());
                if (name == null) {
                    name = violation.getConstraintName();
                }
            }
            if (name == null && cause.getMessage() != null) {
                Matcher matcher = CONSTRAINT_IN_MESSAGE.matcher(cause.getMessage());
                if (matcher.find()) {
                    unique = true;
                    name = matcher.group(1);
                }
            }
        }

        return unique ? Optional.ofNullable(name) : Optional.empty();
    }
}
