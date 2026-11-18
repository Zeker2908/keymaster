package ru.zeker.keymaster.resource;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.validation.Valid;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import lombok.RequiredArgsConstructor;
import ru.zeker.keymaster.dto.request.LoginRequest;
import ru.zeker.keymaster.dto.response.TokenResponse;
import ru.zeker.keymaster.service.AuthService;

@Path("/v1/auth")
@ApplicationScoped
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@RequiredArgsConstructor
public class AuthResource {

    private final AuthService authService;

    @POST
    @Path("/login")
    public Uni<TokenResponse> login(@Valid LoginRequest request) {
        return authService.login(request);
    }
}
