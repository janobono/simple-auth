package sk.janobono.simple.common.security;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import sk.janobono.simple.common.config.CorsConfigProperties;

@RequiredArgsConstructor
@ApplicationScoped
@Provider
public class CorsFilter implements ContainerResponseFilter {

    private final CorsConfigProperties corsConfigProperties;

    @Override
    public void filter(final ContainerRequestContext requestContext, final ContainerResponseContext responseContext) throws IOException {
        final String origin = requestContext.getHeaderString("Origin");
        if (origin != null && corsConfigProperties.allowedOrigins().contains(origin)) {
            responseContext.getHeaders().add("Access-Control-Allow-Origin", origin);
            responseContext.getHeaders().add("Access-Control-Allow-Methods", String.join(",", corsConfigProperties.allowedMethods()));
            responseContext.getHeaders().add("Access-Control-Allow-Headers", String.join(",", corsConfigProperties.allowedHeaders()));
            if (corsConfigProperties.exposedHeaders() != null) {
                responseContext.getHeaders().add("Access-Control-Expose-Headers", String.join(",", corsConfigProperties.exposedHeaders()));
            }
            responseContext.getHeaders().add("Access-Control-Allow-Credentials", String.valueOf(corsConfigProperties.allowCredentials()));
        }
    }
}
