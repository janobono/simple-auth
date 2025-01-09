package sk.janobono.simple.common.security.jwt;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import jakarta.annotation.Priority;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.api.model.User;
import sk.janobono.simple.business.service.UserService;
import sk.janobono.simple.common.component.JwtToken;
import sk.janobono.simple.common.security.SimpleAuthPrincipal;
import sk.janobono.simple.common.security.SimpleAuthSecurityContext;

@RequiredArgsConstructor
@Provider
@Priority(1)
public class JwtAuthenticationFilter implements ContainerRequestFilter {

    private final JwtToken jwtToken;
    private final UserService userService;

    @Override
    public void filter(final ContainerRequestContext requestContext) throws IOException {
        final String authorizationHeader = requestContext.getHeaderString("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            final String token = authorizationHeader.substring(7);
            final Long id = jwtToken.parseToken(token).id();
            final User user = userService.getUser(id);
            final Set<String> roles = user.getAuthorities().stream()
                .map(Authority::toString)
                .collect(Collectors.toSet());

            final SecurityIdentity securityIdentity = QuarkusSecurityIdentity.builder()
                .setPrincipal(new SimpleAuthPrincipal(user))
                .addRoles(roles)
                .build();
            requestContext.setSecurityContext(new SimpleAuthSecurityContext(securityIdentity));
        }
    }
}
