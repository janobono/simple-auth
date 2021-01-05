package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Schema(name = "AuthenticationResponse")
@Getter
@Setter
@ToString
public class AuthenticationResponseSO {

    private String type = "Bearer";

    private String token;

    private Long expiresIn;
}
