package sk.janobono.simple.common.config;

import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("app.verification")
@Validated
public record VerificationConfigProperties(
        @NotEmpty String issuer
) {
}
