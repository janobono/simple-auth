package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.Map;
import java.util.Set;

@Schema(name = "UserDetail")
@Getter
@Setter
@ToString(exclude = {"password"})
public class UserDetailSO {

    private Long id;

    private String username;

    private String password;

    private Boolean enabled;

    private Set<RoleDetailSO> roles;

    private Map<String, String> attributes;
}
