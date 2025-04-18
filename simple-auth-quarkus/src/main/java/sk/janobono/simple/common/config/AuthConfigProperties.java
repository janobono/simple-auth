package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "app.auth")
public interface AuthConfigProperties {

    Integer signUpTokenExpiration();

    Integer resetPasswordTokenExpiration();
}
