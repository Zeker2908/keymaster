package ru.zeker.keymaster.util;

import io.vertx.pgclient.PgException;
import org.hibernate.exception.ConstraintViolationException;

import java.sql.SQLException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DatabaseConstraintViolations {

    public static final String UNIQUE_VIOLATION = "23505";
    public static final String EXCLUSION_VIOLATION = "23P01";
    private static final Pattern CONSTRAINT_IN_MESSAGE =
            Pattern.compile("(?:unique|exclusion) constraint \"([^\"]+)\"");

    private DatabaseConstraintViolations() {
    }

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

            if (cause instanceof SQLException sql && sqlState.equals(sql.getSQLState())) {
                matched = true;
            }

            if (name == null && isDatabaseConstraintFailure(cause)) {
                name = constraintFromMessage(cause.getMessage()).orElse(null);
            }
        }

        return matched ? Optional.ofNullable(name) : Optional.empty();
    }

    private static boolean isDatabaseConstraintFailure(Throwable cause) {
        return cause instanceof PgException
                || cause instanceof ConstraintViolationException
                || cause instanceof SQLException;
    }

    private static Optional<String> constraintFromMessage(String message) {
        if (message == null) {
            return Optional.empty();
        }
        Matcher matcher = CONSTRAINT_IN_MESSAGE.matcher(message);
        return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
    }
}
