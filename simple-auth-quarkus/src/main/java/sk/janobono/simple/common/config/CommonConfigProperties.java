package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.ws.rs.DefaultValue;

@ConfigMapping(prefix = "app.common")
public interface CommonConfigProperties {

    Integer captchaLength();

    String confirmPath();

    String mail();

    String webUrl();
}
