package sk.janobono.simple.common.config;

import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.cors")
public record CorsConfigProperties(
    @NotEmpty List<String> allowedOrigins,
    @NotEmpty List<String> allowedMethods,
    @NotEmpty List<String> allowedHeaders,
    List<String> exposedHeaders,
    boolean allowCredentials
) {

}
