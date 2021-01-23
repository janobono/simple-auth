package sk.janobono.config;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

@Getter
@Setter
@ToString
@ConfigurationProperties("app")
public class ConfigProperties {

    @NotEmpty
    private String issuer;

    @NotEmpty
    private String jwtPrivateKey;

    @NotEmpty
    private String jwtPublicKey;

    @NotNull
    private Integer jwtExpiration;
}
