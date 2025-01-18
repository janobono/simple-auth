package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "app.verification")
public interface VerificationConfigProperties {

    String issuer();
}
