package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.NotEmpty;

@ConfigMapping(prefix = "app.verification")
public interface VerificationConfigProperties {
    @NotEmpty
    String issuer();
}
