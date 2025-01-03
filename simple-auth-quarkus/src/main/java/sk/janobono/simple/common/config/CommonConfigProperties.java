package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.ws.rs.DefaultValue;

@ConfigMapping(prefix = "app.common")
public interface CommonConfigProperties {
    @DefaultValue("4")
    @Min(4)
    Integer captchaLength();

    @NotEmpty
    String confirmPath();

    @NotEmpty
    String mail();

    @NotEmpty
    String webUrl();
}
