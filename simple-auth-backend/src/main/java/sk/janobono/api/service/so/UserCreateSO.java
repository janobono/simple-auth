package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Map;

@Schema(name = "UserCreate")
public record UserCreateSO(
        @NotBlank @Size(max = 255) String username,
        @NotBlank @Size(max = 255) String password,
        @NotNull Boolean enabled,
        List<AuthoritySO> authorities,
        Map<String, String> attributes
) {
    @Override
    public String toString() {
        return "UserCreateSO{" +
                "username='" + username + '\'' +
                ", enabled=" + enabled +
                ", authorities=" + authorities +
                ", attributes=" + attributes +
                '}';
    }
}
