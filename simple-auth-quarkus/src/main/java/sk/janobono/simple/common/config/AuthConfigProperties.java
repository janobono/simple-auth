package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.NotNull;

@ConfigMapping(prefix = "app.auth")
public interface AuthConfigProperties {
    @NotNull
    Integer signUpTokenExpiration();

    @NotNull
    Integer resetPasswordTokenExpiration();
}
