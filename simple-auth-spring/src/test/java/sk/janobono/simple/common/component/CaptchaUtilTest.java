package sk.janobono.simple.common.component;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.common.exception.ApplicationException;

import static org.assertj.core.api.Assertions.assertThat;

class CaptchaUtilTest {

    @Test
    void generateCaptcha_whenNullInput_thenNullResult() {
        // Given
        final CommonConfigProperties commonConfigProperties = new CommonConfigProperties(
                8,
                "/confirm",
                "simple@auth.org",
                "test@test.sk"
        );
        final CaptchaUtil captchaUtil = new CaptchaUtil(commonConfigProperties);

        // When
        final byte[] image = captchaUtil.generateImage(null);
        final String token = captchaUtil.generateToken(null);

        // Then
        assertThat(image).isNull();
        assertThat(token).isNull();
    }

    @Test
    void generateCaptcha_whenValidInput_thenValidResult() {
        // Given
        final CommonConfigProperties commonConfigProperties = new CommonConfigProperties(
                8,
                "/confirm",
                "simple@auth.org",
                "test@test.sk"
        );
        final CaptchaUtil captchaUtil = new CaptchaUtil(commonConfigProperties);

        // When
        final String text = captchaUtil.generateText();
        final byte[] image = captchaUtil.generateImage(text);
        final String token = captchaUtil.generateToken(text);

        // Then
        assertThat(text).isNotBlank();
        assertThat(text).hasSize(commonConfigProperties.captchaLength());
        assertThat(image).isNotNull();
        assertThat(token).isNotBlank();
        assertThat(captchaUtil.isTokenValid(text, token)).isTrue();
    }

    @Test
    void generateCaptcha_whenInvalidInput_thenExceptionThrown() {
        // Given
        final CommonConfigProperties commonConfigProperties = new CommonConfigProperties(
                8,
                "/confirm",
                "simple@auth.org",
                "test@test.sk"
        );
        final CaptchaUtil captchaUtil = new CaptchaUtil(commonConfigProperties);

        // When
        final String text = captchaUtil.generateText();
        final String token = captchaUtil.generateToken(text);

        // Then
        Assertions.assertThrows(
                ApplicationException.class,
                () -> captchaUtil.checkTokenValid("xyz", token)
        );
    }
}
