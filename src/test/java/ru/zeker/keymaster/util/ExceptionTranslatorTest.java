package ru.zeker.keymaster.util;

import io.vertx.pgclient.PgException;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.domain.entity.SigningKey;
import ru.zeker.keymaster.exception.ErrorCode;
import ru.zeker.keymaster.exception.KeyMasterException;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ExceptionTranslatorTest {

    @Test
    void translatesExclusionViolationToScheduleConflict() {
        PgException conflict = mock(PgException.class);
        when(conflict.getSqlState()).thenReturn(DatabaseConstraintViolations.EXCLUSION_VIOLATION);
        when(conflict.getConstraint()).thenReturn(SigningKey.KEY_SCHEDULE_EXCL);

        Throwable translated = ExceptionTranslator.translate(
                new RuntimeException(new IllegalStateException(conflict)));

        KeyMasterException exception = (KeyMasterException) translated;
        assertEquals(ErrorCode.KEY_SCHEDULE_CONFLICT, exception.getCode());
    }

    @Test
    void translatesExclusionViolationWhenConstraintNameOnlyPresentInMessage() {
        SQLException root = new SQLException(
                "ERROR: conflicting key value violates exclusion constraint "
                        + "\"" + SigningKey.KEY_SCHEDULE_EXCL + "\" (23P01)",
                DatabaseConstraintViolations.EXCLUSION_VIOLATION,
                0);
        ConstraintViolationException violation = new ConstraintViolationException(
                "error executing SQL statement", root, "insert into signing_key ...", null);

        Throwable translated = ExceptionTranslator.translate(violation);

        KeyMasterException exception = (KeyMasterException) translated;
        assertEquals(ErrorCode.KEY_SCHEDULE_CONFLICT, exception.getCode());
    }

    @Test
    void leavesUnmappedFailuresUntouched() {
        PgException conflict = mock(PgException.class);
        when(conflict.getSqlState()).thenReturn(DatabaseConstraintViolations.EXCLUSION_VIOLATION);
        when(conflict.getConstraint()).thenReturn("unknown_constraint");

        RuntimeException failure = new RuntimeException(conflict);

        assertSame(failure, ExceptionTranslator.translate(failure));
    }
}
