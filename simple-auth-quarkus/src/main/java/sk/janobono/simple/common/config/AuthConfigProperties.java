package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.NotNull;

@ConfigMapping(prefix = "app.auth")
public interface AuthConfigProperties {

    Integer signUpTokenExpiration();

    Integer resetPasswordTokenExpiration();
}
