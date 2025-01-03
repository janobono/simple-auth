package sk.janobono.simple.api;

import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import sk.janobono.simple.business.service.CaptchaService;

public class CaptchaController implements CaptchaApi {

    @Inject
    CaptchaService captchaService;

    @Override
    public Response getCaptcha() {
        return Response.status(Response.Status.OK)
                .entity(captchaService.getCaptcha())
                .build();
    }
}
