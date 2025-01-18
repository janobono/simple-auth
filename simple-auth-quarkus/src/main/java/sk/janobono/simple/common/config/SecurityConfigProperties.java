package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.NotBlank;

@ConfigMapping(prefix = "app.security")
public interface SecurityConfigProperties {

    String publicPathPatternRegex();
}
