package sk.janobono.simple.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.testcontainers.shaded.com.google.common.net.HttpHeaders;
import sk.janobono.simple.BaseTest;
import sk.janobono.simple.api.model.*;
import sk.janobono.simple.business.model.mail.MailData;
import sk.janobono.simple.common.component.CaptchaUtil;
import sk.janobono.simple.common.config.CommonConfigProperties;

import static org.assertj.core.api.Assertions.assertThat;

class AuthControllerTest extends BaseTest {

    public static final String EMAIL = "jimbo.pytlik@domain.com";
    public static final String FIRST_NAME = "Jimbo";
    public static final String LAST_NAME = "Pytlik";
    public static final String PASSWORD = "simple";
    public static final String NEW_PASSWORD = "newPass123";

    @Autowired
    public CommonConfigProperties commonConfigProperties;

    @Autowired
    public CaptchaUtil captchaUtil;

    @Test
    void fullTest() {
        userRepository.deleteAll();

        final String token = signUp();
        confirm(token);

        AuthenticationResponse authenticationResponse = signIn(EMAIL, PASSWORD);
        authenticationResponse = changeEmail(authenticationResponse);
        authenticationResponse = changePassword(authenticationResponse);
        changeUserDetails(authenticationResponse);

        final String[] data = resetPassword();
        confirm(data[0]);
        signIn(EMAIL, data[1]);
    }

    private String signUp() {
        final String captchaText = captchaUtil.generateText();
        final String captchaToken = captchaUtil.generateToken(captchaText);

        restClient.post()
                .uri(getURI("/auth/sign-up"))
                .body(new SignUp(
                        EMAIL,
                        PASSWORD,
                        FIRST_NAME,
                        LAST_NAME,
                        captchaText,
                        captchaToken
                ))
                .retrieve();

        final MailData mailData = testMail.getMail();
        assertThat(mailData).isNotNull();
        assertThat(mailData.content()).isNotNull();

        final String regex = commonConfigProperties.webUrl() + "/confirm/";
        return mailData.content().mailLink().href().replaceAll(regex, "");
    }

    private void confirm(final String token) {
        restClient.post()
                .uri(getURI("/auth/confirm"))
                .body(new Confirmation(token))
                .retrieve()
                .body(AuthenticationResponse.class);
    }

    private AuthenticationResponse changeEmail(final AuthenticationResponse authenticationResponse) {
        final String captchaText = captchaUtil.generateText();
        final String captchaToken = captchaUtil.generateToken(captchaText);

        restClient.post()
                .uri(getURI("/auth/change-email"))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(new ChangeEmail("a" + EMAIL, PASSWORD, captchaText, captchaToken))
                .retrieve();

        return restClient.post()
                .uri(getURI("/auth/change-email"))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(new ChangeEmail(EMAIL, PASSWORD, captchaText, captchaToken))
                .retrieve()
                .body(AuthenticationResponse.class);
    }

    private AuthenticationResponse changePassword(final AuthenticationResponse authenticationResponse) {
        final String captchaText = captchaUtil.generateText();
        final String captchaToken = captchaUtil.generateToken(captchaText);

        restClient.post()
                .uri(getURI("/auth/change-password"))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(new ChangePassword(PASSWORD, NEW_PASSWORD, captchaText, captchaToken))
                .retrieve();

        return restClient.post()
                .uri(getURI("/auth/change-password"))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(new ChangePassword(NEW_PASSWORD, PASSWORD, captchaText, captchaToken))
                .retrieve()
                .body(AuthenticationResponse.class);
    }

    private void changeUserDetails(final AuthenticationResponse authenticationResponse) {
        final String captchaText = captchaUtil.generateText();
        final String captchaToken = captchaUtil.generateToken(captchaText);

        restClient.post()
                .uri(getURI("/auth/change-user-details"))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(new ChangeUserDetails(
                        FIRST_NAME,
                        LAST_NAME,
                        captchaText,
                        captchaToken
                ))
                .retrieve()
                .body(AuthenticationResponse.class);
    }

    private String[] resetPassword() {
        final String captchaText = captchaUtil.generateText();
        final String captchaToken = captchaUtil.generateToken(captchaText);

        restClient.post()
                .uri(getURI("/auth/reset-password"))
                .body(new ResetPassword(EMAIL, captchaText, captchaToken))
                .retrieve();

        final MailData mailData = testMail.getMail();
        assertThat(mailData).isNotNull();
        assertThat(mailData.content()).isNotNull();
        assertThat(mailData.content().mailLink()).isNotNull();
        assertThat(mailData.content().mailLink().href()).isNotBlank();
        final String regex = commonConfigProperties.webUrl() + "/confirm/";
        final String token = mailData.content().mailLink().href().replaceAll(regex, "");
        final String password = mailData.content().lines().getLast().replaceAll("password: ", "");
        return new String[]{token, password};
    }
}
