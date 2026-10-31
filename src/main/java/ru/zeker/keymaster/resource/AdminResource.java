package ru.zeker.keymaster.resource;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.UserContext;
import ru.zeker.keymaster.resource.filter.RequireAdmin;
import ru.zeker.keymaster.service.AdminService;

@Path("/admin")
@RequireAdmin
@ApplicationScoped
@RequiredArgsConstructor
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class AdminResource {

    private final AdminService service;
    private final UserContext userContext;

    @POST
    @Path("/users")
    public Uni<Response> createUser() {
        return null;
    }
}
