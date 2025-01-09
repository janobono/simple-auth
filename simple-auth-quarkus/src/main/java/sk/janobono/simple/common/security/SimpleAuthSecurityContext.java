package sk.janobono.simple.common.security;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.ws.rs.core.SecurityContext;
import java.security.Principal;

public record SimpleAuthSecurityContext(
    SecurityIdentity securityIdentity
) implements SecurityContext {

    @Override
    public Principal getUserPrincipal() {
        return securityIdentity.getPrincipal();
    }

    @Override
    public boolean isUserInRole(final String role) {
        return securityIdentity.hasRole(role);
    }

    @Override
    public boolean isSecure() {
        return true;
    }

    @Override
    public String getAuthenticationScheme() {
        return "Bearer";
    }
}
