package ru.zeker.keymaster.util;

import io.vertx.pgclient.PgException;
import org.hibernate.exception.ConstraintViolationException;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DatabaseConstraintViolations {

    public static final String UNIQUE_VIOLATION = "23505";
    public static final String EXCLUSION_VIOLATION = "23P01";
    private static final Pattern CONSTRAINT_IN_MESSAGE =
            Pattern.compile("unique constraint \"([^\"]+)\"");

    private DatabaseConstraintViolations() {}

    public static Optional<String> constraintName(Throwable failure, String sqlState) {
        String name = null;
        boolean matched = false;

        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof PgException pg) {
                if (sqlState.equals(pg.getSqlState())) {
                    matched = true;
                }
                if (name == null) {
                    name = pg.getConstraint();
                }
            }

            if (cause instanceof ConstraintViolationException violation) {
                if (sqlState.equals(violation.getSQLState())) {
                    matched = true;
                }
                if (name == null) {
                    name = violation.getConstraintName();
                }
            }
        }

        return matched ? Optional.ofNullable(name) : Optional.empty();
    }

}
