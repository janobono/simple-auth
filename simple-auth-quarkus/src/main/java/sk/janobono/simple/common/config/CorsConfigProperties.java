package sk.janobono.simple.common.config;

import io.smallrye.config.ConfigMapping;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

@ConfigMapping(prefix = "app.cors")
public interface CorsConfigProperties {

    List<String> allowedOrigins();

    List<String> allowedMethods();

    List<String> allowedHeaders();

    List<String> exposedHeaders();

    boolean allowCredentials();
}
