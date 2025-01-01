package sk.janobono.simple.api;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RestController;
import sk.janobono.simple.api.model.Captcha;
import sk.janobono.simple.business.service.CaptchaService;

@RequiredArgsConstructor
@RestController
public class CaptchaController implements CaptchaApi {

    private final CaptchaService captchaService;

    @Override
    public Captcha getCaptcha() {
        return captchaService.getCaptcha();
    }
}
