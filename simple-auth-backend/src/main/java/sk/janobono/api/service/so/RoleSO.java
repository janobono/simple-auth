package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;

@Schema(name = "Role")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class RoleSO {

    public static final String ROLE_VIEW_USERS = "view-users";
    public static final String ROLE_MANAGE_USERS = "manage-users";

    @NotEmpty
    @Size(max = 255)
    private String name;
}
