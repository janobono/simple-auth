package sk.janobono.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@ConfigurationProperties("app")
@ConstructorBinding
@Validated
public record ConfigProperties(
        @NotEmpty String issuer,
        @NotEmpty String jwtPrivateKey,
        @NotEmpty String jwtPublicKey,
        @NotNull Integer jwtExpiration
) {
}
