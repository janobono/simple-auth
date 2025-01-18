package sk.janobono.simple.common.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties("app.common")
@Validated
public record CommonConfigProperties(
    @DefaultValue("4") @Min(4) Integer captchaLength,
    @NotEmpty String confirmPath,
    @NotEmpty String mail,
    @NotEmpty String webUrl
) {

}
