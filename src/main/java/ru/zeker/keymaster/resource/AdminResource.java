package ru.zeker.keymaster.resource;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.context.Actor;
import ru.zeker.keymaster.domain.context.RequestContext;
import ru.zeker.keymaster.dto.request.NewUserRequest;
import ru.zeker.keymaster.resource.filter.RequireAdmin;
import ru.zeker.keymaster.service.PrincipalService;

@Path("/admin")
@RequireAdmin
@ApplicationScoped
@RequiredArgsConstructor
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class AdminResource {

    private final PrincipalService service;
    private final RequestContext context;

    @POST
    @Path("/users")
    public Uni<Response> createUser(@Valid NewUserRequest request) {
        Actor actor = context.actor();
        return service.create(actor, request)
                .map(userView -> Response.status(Response.Status.CREATED).entity(userView).build());
    }
}
