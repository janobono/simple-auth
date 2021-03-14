package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Schema(name = "UserCreate")
@Getter
@Setter
@ToString(exclude = "password")
public class UserCreateSO {

    @NotEmpty
    @Size(max = 255)
    private String username;

    @NotEmpty
    @Size(max = 255)
    private String password;

    @NotNull
    private Boolean enabled;

    private List<AuthoritySO> authorities;

    private Map<String, String> attributes;

    public List<AuthoritySO> getAuthorities() {
        if (authorities == null) {
            authorities = new ArrayList<>();
        }
        return authorities;
    }

    public Map<String, String> getAttributes() {
        if (attributes == null) {
            attributes = new HashMap<>();
        }
        return attributes;
    }
}
