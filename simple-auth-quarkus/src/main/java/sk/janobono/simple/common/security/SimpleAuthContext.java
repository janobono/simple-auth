package sk.janobono.simple.common.security;

import io.quarkus.security.ForbiddenException;
import io.quarkus.security.UnauthorizedException;
import jakarta.enterprise.context.RequestScoped;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.api.model.User;

@RequestScoped
public class SimpleAuthContext {

  private User user;

  public User getUser() {
    if (user == null) {
      throw new UnauthorizedException("Error -> Unauthorized");
    }
    return user;
  }

  public void setUser(final User user) {
    this.user = user;
  }

  public void hasAnyAuthority(final Authority... authorities) {
    for (final Authority authority : authorities) {
      if (user.getAuthorities().contains(authority)) {
        return;
      }
    }
    throw new ForbiddenException("Error -> Forbidden");
  }
}
