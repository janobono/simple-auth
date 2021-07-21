package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@Schema(name = "User")
public record UserSO(
        Long id,
        String username,
        Boolean enabled,
        List<AuthoritySO> authorities,
        Map<String, String> attributes
) {
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserSO userSO = (UserSO) o;
        return Objects.equals(id, userSO.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }
}
