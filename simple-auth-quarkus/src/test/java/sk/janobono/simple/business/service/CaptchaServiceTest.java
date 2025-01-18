package sk.janobono.simple.business.service;

import static org.assertj.core.api.Assertions.assertThat;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import sk.janobono.simple.api.model.Captcha;

@QuarkusTest
class CaptchaServiceTest {

    @Inject
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
