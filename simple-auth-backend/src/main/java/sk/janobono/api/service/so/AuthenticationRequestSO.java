package sk.janobono.api.service.so;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;

@Schema(name = "AuthenticationRequest")
@Getter
@Setter
@ToString(exclude = {"password"})
public class AuthenticationRequestSO {

    @NotEmpty
    @Size(max = 255)
    private String username;

    @NotEmpty
    @Size(max = 255)
    private String password;
}
