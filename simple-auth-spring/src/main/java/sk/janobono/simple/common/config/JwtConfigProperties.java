package sk.janobono.simple.common.config;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("app.jwt")
@Validated
public record JwtConfigProperties(
        @NotEmpty String issuer,
        @NotNull Integer expiration
) {
}
