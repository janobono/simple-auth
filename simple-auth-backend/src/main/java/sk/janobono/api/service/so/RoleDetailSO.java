package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Schema(name = "RoleDetail")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class RoleDetailSO {

    private Long id;

    private String name;
}
