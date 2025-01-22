package sk.janobono.simple.common.security;

import io.quarkus.security.identity.SecurityIdentity;
import jakarta.ws.rs.core.SecurityContext;
import java.security.Principal;

public class SimpleAuthSecurityContext implements SecurityContext {

    private final SecurityIdentity securityIdentity;

    public SimpleAuthSecurityContext(final SecurityIdentity securityIdentity) {
        this.securityIdentity = securityIdentity;
    }

    @Override
    public Principal getUserPrincipal() {
        return securityIdentity.getPrincipal();
    }

    @Override
    public boolean isUserInRole(final String role) {
        return securityIdentity.getRoles().contains(role);
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