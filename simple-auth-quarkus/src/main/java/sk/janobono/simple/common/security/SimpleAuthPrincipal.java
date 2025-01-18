package sk.janobono.simple.common.security;

import java.security.Principal;
import sk.janobono.simple.api.model.User;

public record SimpleAuthPrincipal(User user) implements Principal {

    @Override
    public String getName() {
        return user().getEmail();
    }
}
