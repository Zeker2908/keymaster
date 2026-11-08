package ru.zeker.keymaster.resource;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.service.jwk.JwksBuilder;

@Path("/jwks")
@ApplicationScoped
@RequiredArgsConstructor
@Produces(MediaType.APPLICATION_JSON)
public class JwksResource {

    private final JwksBuilder jwksBuilder;

    @GET
    public Uni<Response> jwks() {
        return jwksBuilder.getJwks()
                .map(jwks -> Response.ok(jwks.toJSONObject())
                        .header(HttpHeaders.CACHE_CONTROL, "no-cache")
                        .build());
    }
}
