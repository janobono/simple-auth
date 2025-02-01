package sk.janobono.simple.common.security;

import io.quarkus.logging.Log;
import io.quarkus.security.UnauthorizedException;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;
import java.security.Principal;
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
  private final SimpleAuthContext simpleAuthContext;

  public JwtAuthenticationFilter(final SecurityConfigProperties securityConfigProperties,
      final JwtToken jwtToken, final UserService userService,
      final SimpleAuthContext simpleAuthContext) {
    this.jwtToken = jwtToken;
    this.userService = userService;
    this.publicPathPattern = Pattern.compile(securityConfigProperties.publicPathPatternRegex());
    this.simpleAuthContext = simpleAuthContext;
  }

  @Override
  public void filter(final ContainerRequestContext requestContext) {
    final String path = requestContext.getUriInfo().getPath();
    Log.debug("Request path: " + path);
    if (publicPathPattern.matcher(path).matches()) {
      return;
    }

    final String authorizationHeader = requestContext.getHeaderString("Authorization");
    Log.debug("Authorization header: " + authorizationHeader);
    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
      final String token = authorizationHeader.substring(7);
      final Long id = jwtToken.parseToken(token).id();
      Log.debug("Parsed user ID: " + id);
      final User user = userService.getUser(id);
      final Set<String> roles = user.getAuthorities().stream()
          .map(Authority::toString)
          .collect(Collectors.toSet());

      requestContext.setSecurityContext(new SecurityContext() {
        @Override
        public Principal getUserPrincipal() {
          return user::getEmail;
        }

        @Override
        public boolean isUserInRole(final String role) {
          return roles.contains(role);
        }

        @Override
        public boolean isSecure() {
          return false;
        }

        @Override
        public String getAuthenticationScheme() {
          return SecurityContext.BASIC_AUTH;
        }
      });
      simpleAuthContext.setUser(user);
      Log.debug("SecurityContext set in request context");
      return;
    }

    throw new UnauthorizedException("Error -> Unauthorized");
  }
}