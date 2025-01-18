package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "app.security")
public interface SecurityConfigProperties {

    String publicPathPatternRegex();
}
