package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Schema(name = "RoleDetail")
@Getter
@Setter
@ToString
public class RoleDetailSO {

    private Long id;

    private String name;
}
