package sk.janobono.simple.common.component;

import static org.assertj.core.api.Assertions.assertThat;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.common.exception.ApplicationException;

@QuarkusTest
class CaptchaUtilTest {

    @Test
    void generateCaptcha_whenNullInput_thenNullResult() {
        // Given
        final CommonConfigProperties commonConfigProperties = new CommonConfigProperties() {
            @Override
            public Integer captchaLength() {
                return 8;
            }

            @Override
            public String confirmPath() {
                return "/confirm";
            }

            @Override
            public String mail() {
                return "simple@auth.org";
            }

            @Override
            public String webUrl() {
                return "test@test.sk";
            }
        };
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
        final CommonConfigProperties commonConfigProperties = new CommonConfigProperties() {
            @Override
            public Integer captchaLength() {
                return 8;
            }

            @Override
            public String confirmPath() {
                return "/confirm";
            }

            @Override
            public String mail() {
                return "simple@auth.org";
            }

            @Override
            public String webUrl() {
                return "test@test.sk";
            }
        };
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
        final CommonConfigProperties commonConfigProperties = new CommonConfigProperties() {
            @Override
            public Integer captchaLength() {
                return 8;
            }

            @Override
            public String confirmPath() {
                return "/confirm";
            }

            @Override
            public String mail() {
                return "simple@auth.org";
            }

            @Override
            public String webUrl() {
                return "test@test.sk";
            }
        };
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
