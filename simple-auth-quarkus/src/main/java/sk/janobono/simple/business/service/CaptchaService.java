package sk.janobono.simple.business.service;

import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;
import sk.janobono.simple.api.model.Captcha;
import sk.janobono.simple.common.component.CaptchaUtil;

import java.util.Base64;

@RequiredArgsConstructor
@ApplicationScoped
public class CaptchaService {

    private final CaptchaUtil captchaUtil;

    public Captcha getCaptcha() {
        final String text = captchaUtil.generateText();
        final String image = "data:image/png;base64," + Base64.getEncoder().encodeToString(captchaUtil.generateImage(text));
        final String token = captchaUtil.generateToken(text);
        return Captcha.builder().captchaToken(token).captchaImage(image).build();
    }
}
