package sk.janobono.simple.common.security;

import sk.janobono.simple.api.model.User;

import java.security.Principal;

public record SimpleAuthPrincipal(User user) implements Principal {
    @Override
    public String getName() {
        return user().getEmail();
    }
}
