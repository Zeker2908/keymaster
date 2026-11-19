package ru.zeker.keymaster.util;

import io.vertx.pgclient.PgException;
import org.junit.jupiter.api.Test;
import ru.zeker.keymaster.domain.entity.SigningKey;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DatabaseConstraintViolationsTest {

    @Test
    void findsConstraintNameForMatchingSqlState() {
        PgException conflict = mock(PgException.class);
        when(conflict.getSqlState()).thenReturn(DatabaseConstraintViolations.EXCLUSION_VIOLATION);
        when(conflict.getConstraint()).thenReturn(SigningKey.KEY_SCHEDULE_EXCL);

        assertEquals(Optional.of(SigningKey.KEY_SCHEDULE_EXCL),
                DatabaseConstraintViolations.constraintName(
                        new RuntimeException(new IllegalStateException(conflict)),
                        DatabaseConstraintViolations.EXCLUSION_VIOLATION));
    }

    @Test
    void ignoresOtherSqlStates() {
        PgException conflict = mock(PgException.class);
        when(conflict.getSqlState()).thenReturn(DatabaseConstraintViolations.EXCLUSION_VIOLATION);

        assertEquals(Optional.empty(),
                DatabaseConstraintViolations.constraintName(
                        conflict, DatabaseConstraintViolations.UNIQUE_VIOLATION));
    }
}
