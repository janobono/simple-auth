package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.*;

@Schema(name = "UserDetail")
@Getter
@Setter
@EqualsAndHashCode(of = "id")
@ToString(exclude = "password")
public class UserDetailSO {

    private Long id;

    private String username;

    private String password;

    private Boolean enabled;

    private List<RoleDetailSO> roles;

    private Map<String, String> attributes;

    public List<RoleDetailSO> getRoles() {
        if (roles == null) {
            roles = new ArrayList<>();
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
