package sk.janobono.simple.common.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("app.security")
@Validated
public record SecurityConfigProperties(
    @NotBlank String publicPathPatternRegex
) {

}
