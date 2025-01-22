package sk.janobono.simple.common.security;

import io.quarkus.logging.Log;
import io.quarkus.security.UnauthorizedException;
import io.quarkus.security.identity.SecurityIdentity;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@ApplicationScoped
public class SimpleAuthPrincipalService {

    public SimpleAuthPrincipal getSimpleAuthPrincipal() {
        final SecurityIdentity securityIdentity = JwtAuthenticationFilter.getSecurityIdentity();
        Log.debug("SecurityIdentity: " + securityIdentity);
        if (securityIdentity.isAnonymous()) {
            throw new UnauthorizedException("Error -> Unauthorized");
        }
        return (SimpleAuthPrincipal) securityIdentity.getPrincipal();
    }
}