package sk.janobono.simple.api;

import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import sk.janobono.simple.api.model.*;
import sk.janobono.simple.business.service.AuthService;

@RequiredArgsConstructor
public class AuthController implements AuthApi {

    private final AuthService authService;

    @Override
    public Response changeEmail(final ChangeEmail changeEmail) {
        return Response.status(Response.Status.OK)
                .entity(authService.changeEmail(changeEmail))
                .build();
    }

    @Override
    public Response changePassword(final ChangePassword changePassword) {
        return Response.status(Response.Status.OK)
                .entity(authService.changePassword(changePassword))
                .build();
    }

    @Override
    public Response changeUserDetails(final ChangeUserDetails changeUserDetails) {
        return Response.status(Response.Status.OK)
                .entity(authService.changeUserDetails(changeUserDetails))
                .build();
    }

    @Override
    public Response confirm(final Confirmation confirmation) {
        return Response.status(Response.Status.OK)
                .entity(authService.confirm(confirmation))
                .build();
    }

    @Override
    public Response getUserDetail() {
        return Response.status(Response.Status.OK)
                .entity(authService.getUserDetail())
                .build();
    }

    @Override
    public Response resetPassword(final ResetPassword resetPassword) {
        authService.resetPassword(resetPassword);
        return Response.status(Response.Status.OK)
                .build();
    }

    @Override
    public Response signIn(final SignIn signIn) {
        return Response.status(Response.Status.OK)
                .entity(authService.signIn(signIn))
                .build();
    }

    @Override
    public Response signUp(final SignUp signUp) {
        return Response.status(Response.Status.CREATED)
                .entity(authService.signUp(signUp))
                .build();
    }
}
