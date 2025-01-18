package sk.janobono.simple.common.security;

import io.quarkus.security.UnauthorizedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.api.model.User;
import sk.janobono.simple.business.service.UserService;
import sk.janobono.simple.common.component.JwtToken;
import sk.janobono.simple.common.config.SecurityConfigProperties;

@ApplicationScoped
@Provider
@Priority(1)
public class JwtAuthenticationFilter implements ContainerRequestFilter {

    private final JwtToken jwtToken;
    private final UserService userService;

    private final Pattern publicPathPattern;

    public JwtAuthenticationFilter(final SecurityConfigProperties securityConfigProperties, final JwtToken jwtToken, final UserService userService) {
        this.jwtToken = jwtToken;
        this.userService = userService;

        publicPathPattern = Pattern.compile(securityConfigProperties.publicPathPatternRegex());
    }

    @Override
    public void filter(final ContainerRequestContext requestContext) throws IOException {
        final String path = requestContext.getUriInfo().getPath();
        if (publicPathPattern.matcher(path).matches()) {
            return;
        }

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
            return;
        }

        throw new UnauthorizedException("Error -> Unauthorized");
    }
}
