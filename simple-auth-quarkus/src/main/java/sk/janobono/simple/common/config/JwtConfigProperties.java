package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "app.jwt")
public interface JwtConfigProperties {

    String issuer();

    Integer expiration();
}
