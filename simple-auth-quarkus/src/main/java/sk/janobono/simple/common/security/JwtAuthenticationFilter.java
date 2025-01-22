package sk.janobono.simple.common.security;

import io.quarkus.security.UnauthorizedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.api.model.User;
import sk.janobono.simple.business.service.UserService;
import sk.janobono.simple.common.component.JwtToken;
import sk.janobono.simple.common.config.SecurityConfigProperties;

@ApplicationScoped
@Provider
@Priority(1)
public class JwtAuthenticationFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(JwtAuthenticationFilter.class);
    private static final ThreadLocal<SecurityIdentity> SECURITY_IDENTITY_THREAD_LOCAL = new ThreadLocal<>();

    private final JwtToken jwtToken;
    private final UserService userService;
    private final Pattern publicPathPattern;

    public JwtAuthenticationFilter(final SecurityConfigProperties securityConfigProperties, final JwtToken jwtToken, final UserService userService) {
        this.jwtToken = jwtToken;
        this.userService = userService;
        this.publicPathPattern = Pattern.compile(securityConfigProperties.publicPathPatternRegex());
    }

    @Override
    public void filter(final ContainerRequestContext requestContext) {
        final String path = requestContext.getUriInfo().getPath();
        LOG.debug("Request path: " + path);
        if (publicPathPattern.matcher(path).matches()) {
            return;
        }

        final String authorizationHeader = requestContext.getHeaderString("Authorization");
        LOG.debug("Authorization header: " + authorizationHeader);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            final String token = authorizationHeader.substring(7);
            final Long id = jwtToken.parseToken(token).id();
            LOG.debug("Parsed user ID: " + id);
            final User user = userService.getUser(id);
            final Set<String> roles = user.getAuthorities().stream()
                .map(Authority::toString)
                .collect(Collectors.toSet());

            final SecurityIdentity securityIdentity = QuarkusSecurityIdentity.builder()
                .setPrincipal(new SimpleAuthPrincipal(user))
                .addRoles(roles)
                .build();

            LOG.debug("SecurityIdentity: " + securityIdentity);
            if (securityIdentity == null || securityIdentity.isAnonymous()) {
                throw new UnauthorizedException("Error -> Unauthorized: SecurityIdentity is null or anonymous");
            }

            SECURITY_IDENTITY_THREAD_LOCAL.set(securityIdentity);
            requestContext.setSecurityContext(new SimpleAuthSecurityContext(securityIdentity));
            LOG.debug("SecurityContext set in request context");
            return;
        }

        throw new UnauthorizedException("Error -> Unauthorized");
    }

    public static SecurityIdentity getSecurityIdentity() {
        return SECURITY_IDENTITY_THREAD_LOCAL.get();
    }
}