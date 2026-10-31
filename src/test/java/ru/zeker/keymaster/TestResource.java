package ru.zeker.keymaster;

import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.sqlclient.Pool;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.slf4j.MDC;

import java.time.Duration;
import java.util.Map;

@Path("/test")
@Produces(MediaType.TEXT_PLAIN)
public class TestResource {

    @Inject
    Pool pool;

    @GET
    @Path("/mdc")
    public Uni<String> testMdc() {
        return pool.query("SELECT 1").execute()
                .map(rows -> MDC.get("requestId"));
    }

    @GET
    @Path("/mdc/delay")
    public Uni<String> testMdcWithDelay() {
        return Uni.createFrom().voidItem()
                .onItem().delayIt().by(Duration.ofMillis(100))
                .map(ignored -> MDC.get("requestId"));
    }

    @GET
    @Path("/fail")
    public String fail() {
        throw new IllegalStateException("Sensitive internal details");
    }

    @POST
    @Path("/json")
    @Consumes(MediaType.APPLICATION_JSON)
    public Map<String, String> acceptJson(Map<String, String> body) {
        return body;
    }
}
