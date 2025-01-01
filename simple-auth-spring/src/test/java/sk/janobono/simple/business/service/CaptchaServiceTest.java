package sk.janobono.simple.business.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import sk.janobono.simple.BaseTest;
import sk.janobono.simple.api.model.Captcha;

import static org.assertj.core.api.Assertions.assertThat;

class CaptchaServiceTest extends BaseTest {

    @Autowired
    public CaptchaService captchaService;

    @Test
    void getCaptcha_when_then() {
        // WHEN
        final Captcha captcha = captchaService.getCaptcha();

        // THEN
        assertThat(captcha).isNotNull();
        assertThat(captcha.getCaptchaImage()).isNotBlank();
        assertThat(captcha.getCaptchaToken()).isNotBlank();
    }
}
