package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Schema(name = "User")
@Getter
@Setter
@ToString(exclude = {"password"})
public class UserSO {

    private String username;

    private String password;

    private Boolean enabled;

    private Set<RoleSO> roles;

    private Map<String, String> attributes;

    public Set<RoleSO> getRoles() {
        if (roles == null) {
            roles = new HashSet<>();
        }
        return roles;
    }

    public Map<String, String> getAttributes() {
        if (attributes == null) {
            attributes = new HashMap<>();
        }
        return attributes;
    }
}
