package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Schema(name = "AuthenticationRequest")
public record AuthenticationRequestSO(
        @NotBlank @Size(max = 255) String username,
        @NotBlank @Size(max = 255) String password
) {
    @Override
    public String toString() {
        return "AuthenticationRequestSO{" +
                "username='" + username + '\'' +
                '}';
    }
}
