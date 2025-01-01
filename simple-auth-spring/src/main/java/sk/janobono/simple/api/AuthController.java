package sk.janobono.simple.api;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RestController;
import sk.janobono.simple.api.model.*;
import sk.janobono.simple.business.service.AuthService;

@RequiredArgsConstructor
@RestController
public class AuthController implements AuthApi {

    private final AuthService authService;

    @Override
    public AuthenticationResponse changeEmail(final ChangeEmail changeEmail) {
        return authService.changeEmail(changeEmail);
    }

    @Override
    public AuthenticationResponse changePassword(final ChangePassword changePassword) {
        return authService.changePassword(changePassword);
    }

    @Override
    public AuthenticationResponse changeUserDetails(final ChangeUserDetails changeUserDetails) {
        return authService.changeUserDetails(changeUserDetails);
    }

    @Override
    public AuthenticationResponse confirm(final Confirmation confirmation) {
        return authService.confirm(confirmation);
    }

    @Override
    public User getUserDetail() {
        return authService.getUserDetail();
    }

    @Override
    public void resetPassword(final ResetPassword resetPassword) {
        authService.resetPassword(resetPassword);
    }

    @Override
    public AuthenticationResponse signIn(final SignIn signIn) {
        return authService.signIn(signIn);
    }

    @Override
    public AuthenticationResponse signUp(final SignUp signUp) {
        return authService.signUp(signUp);
    }
}
