package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;

@ConfigMapping(prefix = "app.common")
public interface CommonConfigProperties {

    Integer captchaLength();

    String confirmPath();

    String mail();

    String webUrl();
}
