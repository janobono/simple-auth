package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.List;
import java.util.Map;

@Schema(name = "UserUpdate")
public record UserUpdateSO(
        @NotBlank @Size(max = 255) String username,
        String password,
        @NotNull Boolean enabled,
        List<AuthoritySO> authorities,
        Map<String, String> attributes
) {
    @Override
    public String toString() {
        return "UserUpdateSO{" +
                "username='" + username + '\'' +
                ", enabled=" + enabled +
                ", authorities=" + authorities +
                ", attributes=" + attributes +
                '}';
    }
}
