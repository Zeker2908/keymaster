package ru.zeker.keymaster;

import io.quarkus.test.junit.QuarkusTest;
import io.vertx.mutiny.sqlclient.Pool;
import jakarta.inject.Inject;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@QuarkusTest
class FlywayReactiveSmokeTest {

    @Inject
    Pool pool;      // реактивная сторона

    @Inject
    Flyway flyway;    // JDBC-сторона

    @Test
    void shouldHaveNoPendingMigrations() {
        var info = flyway.info();

        assertEquals(0, info.pending().length, "There are pending Flyway migrations");
        assertNotNull(info.current(), "Flyway has not applied any migrations");
    }

    @Test
    void historyTableLivesInKeymasterSchema() {
        Long cnt = pool.query("""
                        SELECT count(*) AS c FROM information_schema.tables
                        WHERE table_schema = 'keymaster' AND table_name = 'flyway_schema_history'
                        """)
                .execute()
                .map(rows -> rows.iterator().next().getLong("c"))
                .await().atMost(Duration.ofSeconds(5));
        assertEquals(1L, cnt);
    }
}