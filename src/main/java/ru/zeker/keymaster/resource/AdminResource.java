package ru.zeker.keymaster.resource;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.domain.Patterns;
import ru.zeker.keymaster.domain.context.RequestContext;
import ru.zeker.keymaster.dto.request.NewRoleRequest;
import ru.zeker.keymaster.dto.request.NewUserRequest;
import ru.zeker.keymaster.dto.response.UserResponse;
import ru.zeker.keymaster.resource.filter.RequireAdmin;
import ru.zeker.keymaster.service.PrincipalService;
import ru.zeker.keymaster.service.RoleService;

import java.util.UUID;

@Path("/admin")
@RequireAdmin
@ApplicationScoped
@RequiredArgsConstructor
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class AdminResource {

    private final PrincipalService principals;
    private final RequestContext context;
    private final RoleService roles;

    @POST
    @Path("/users")
    public Uni<Response> createUser(@Valid NewUserRequest request) {
        return principals.create(context.actor(), request)
                .map(user -> Response.created(
                                UriBuilder.fromPath("/admin/users/{id}").build(user.id()))
                        .entity(user)
                        .build());
    }

    @GET
    @Path("/users/{id}")
    public Uni<UserResponse> getUser(@PathParam("id")
                                     @Pattern(regexp = Patterns.UUID, message = "must be a valid UUID")
                                     String id) {
        return principals.getById(UUID.fromString(id));
    }

    @PUT
    @Path("/users/{id}/roles/{role}")
    public Uni<Response> assignRole(
            @PathParam("id")
            @Pattern(regexp = Patterns.UUID, message = "must be a valid UUID")
            String id,
            @PathParam("role")
            @Pattern(regexp = Patterns.ROLE_NAME, message = "must be a valid role name")
            String role) {
        return principals.assignRole(context.actor(), UUID.fromString(id), role)
                .replaceWith(Response.noContent().build());
    }

    @DELETE
    @Path("/users/{id}/roles/{role}")
    public Uni<Response> revokeRole(
            @PathParam("id")
            @Pattern(regexp = Patterns.UUID, message = "must be a valid UUID")
            String id,
            @PathParam("role")
            @Pattern(regexp = Patterns.ROLE_NAME, message = "must be a valid role name")
            String role) {
        return principals.revokeRole(context.actor(), UUID.fromString(id), role)
                .replaceWith(Response.noContent().build());
    }

    @POST
    @Path("/admin/roles")
    public Uni<Response> addRole(@Valid NewRoleRequest request) {
        return roles.create(context.actor(), request)
                .map((response) -> Response.status(Response.Status.CREATED).entity(response).build());
    }
}
