package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "AuthenticationResponse")
public record AuthenticationResponseSO(
        String bearer
) {
}
