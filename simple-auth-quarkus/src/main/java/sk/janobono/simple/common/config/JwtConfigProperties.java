package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@ConfigMapping(prefix = "app.jwt")
public interface JwtConfigProperties {

    String issuer();

    Integer expiration();
}
