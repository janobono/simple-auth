package sk.janobono.simple.common.config;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("app.auth")
@Validated
public record AuthConfigProperties(
        @NotNull Integer signUpTokenExpiration,
        @NotNull Integer resetPasswordTokenExpiration
) {
}
