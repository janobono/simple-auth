package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Objects;

@Schema(name = "Authority")
public record AuthoritySO(
        Long id,
        String name
) {
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthoritySO that = (AuthoritySO) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }
}

