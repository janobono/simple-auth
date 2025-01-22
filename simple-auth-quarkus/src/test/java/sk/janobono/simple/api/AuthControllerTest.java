package sk.janobono.simple.api;

import static io.restassured.RestAssured.given;
import static jakarta.ws.rs.core.Response.Status.CREATED;
import static jakarta.ws.rs.core.Response.Status.OK;
import static org.assertj.core.api.Assertions.assertThat;

import io.quarkus.test.InjectMock;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sk.janobono.simple.TestMail;
import sk.janobono.simple.api.model.AuthenticationResponse;
import sk.janobono.simple.api.model.ChangeEmail;
import sk.janobono.simple.api.model.ChangePassword;
import sk.janobono.simple.api.model.ChangeUserDetails;
import sk.janobono.simple.api.model.Confirmation;
import sk.janobono.simple.api.model.ResetPassword;
import sk.janobono.simple.api.model.SignIn;
import sk.janobono.simple.api.model.SignUp;
import sk.janobono.simple.business.model.mail.MailData;
import sk.janobono.simple.business.service.MailService;
import sk.janobono.simple.common.component.CaptchaUtil;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.dal.repository.UserRepository;

@QuarkusTest
class AuthControllerTest {

    public static final String EMAIL = "jimbo.pytlik@domain.com";
    public static final String FIRST_NAME = "Jimbo";
    public static final String LAST_NAME = "Pytlik";
    public static final String PASSWORD = "simple";
    public static final String NEW_PASSWORD = "newPass123";

    @Inject
    public CommonConfigProperties commonConfigProperties;

    @Inject
    public CaptchaUtil captchaUtil;

    @Inject
    public UserRepository userRepository;

    @InjectMock
    public MailService mailService;
    protected TestMail testMail;

    @BeforeEach
    public void setUp() {
        testMail = new TestMail();
        testMail.mock(mailService);
    }

    @Test
    @Transactional
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

        given()
            .contentType("application/json")
            .body(SignUp.builder()
                .email(EMAIL)
                .password(PASSWORD)
                .firstName(FIRST_NAME)
                .lastName(LAST_NAME)
                .captchaText(captchaText)
                .captchaToken(captchaToken)
                .build())
            .when()
            .post("/auth/sign-up")
            .then()
            .statusCode(CREATED.getStatusCode());

        final MailData mailData = testMail.getMail();
        assertThat(mailData).isNotNull();
        assertThat(mailData.content()).isNotNull();

        final String regex = commonConfigProperties.webUrl() + "/confirm/";
        return mailData.content().mailLink().href().replaceAll(regex, "");
    }

    private void confirm(final String token) {
        given()
            .contentType("application/json")
            .body(Confirmation.builder()
                .token(token)
                .build())
            .when()
            .post("/auth/confirm")
            .then()
            .statusCode(OK.getStatusCode());
    }

    private AuthenticationResponse changeEmail(final AuthenticationResponse authenticationResponse) {
        final String captchaText = captchaUtil.generateText();
        final String captchaToken = captchaUtil.generateToken(captchaText);

        given()
            .header("Authorization", "Bearer " + authenticationResponse.getToken())
            .contentType("application/json")
            .body(ChangeEmail.builder().email("a" + EMAIL).password(PASSWORD).captchaText(captchaText).captchaToken(captchaToken).build())
            .when()
            .post("/auth/change-email")
            .then()
            .statusCode(OK.getStatusCode());

        final Response response = given()
            .contentType("application/json")
            .header("Authorization", "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
            .body(ChangeEmail.builder().email(EMAIL).password(PASSWORD).captchaText(captchaText).captchaToken(captchaToken).build())
            .when()
            .post("/auth/change-email")
            .then()
            .statusCode(OK.getStatusCode())
            .extract().response();

        return response.getBody().as(AuthenticationResponse.class);
    }

    private AuthenticationResponse changePassword(final AuthenticationResponse authenticationResponse) {
        final String captchaText = captchaUtil.generateText();
        final String captchaToken = captchaUtil.generateToken(captchaText);

        given()
            .contentType("application/json")
            .header("Authorization", "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
            .body(
                ChangePassword.builder().oldPassword(PASSWORD).newPassword(NEW_PASSWORD).captchaText(captchaText).captchaToken(captchaToken).build())
            .when()
            .post("/auth/change-password")
            .then()
            .statusCode(OK.getStatusCode());

        final Response response = given()
            .contentType("application/json")
            .header("Authorization", "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
            .body(
                ChangePassword.builder().oldPassword(NEW_PASSWORD).newPassword(PASSWORD).captchaText(captchaText).captchaToken(captchaToken).build())
            .when()
            .post("/auth/change-password")
            .then()
            .statusCode(OK.getStatusCode())
            .extract().response();

        return response.getBody().as(AuthenticationResponse.class);
    }

    private void changeUserDetails(final AuthenticationResponse authenticationResponse) {
        final String captchaText = captchaUtil.generateText();
        final String captchaToken = captchaUtil.generateToken(captchaText);

        final Response response = given()
            .contentType("application/json")
            .header("Authorization", "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
            .body(ChangeUserDetails.builder()
                .firstName(FIRST_NAME)
                .lastName(LAST_NAME)
                .captchaText(captchaText)
                .captchaToken(captchaToken)
                .build())
            .when()
            .post("/auth/change-user-details")
            .then()
            .statusCode(OK.getStatusCode())
            .extract().response();

        assertThat(response.getBody().as(AuthenticationResponse.class)).isNotNull();
    }

    private String[] resetPassword() {
        final String captchaText = captchaUtil.generateText();
        final String captchaToken = captchaUtil.generateToken(captchaText);

        given()
            .contentType("application/json")
            .body(ResetPassword.builder().email(EMAIL).captchaText(captchaText).captchaToken(captchaToken).build())
            .when()
            .post("/auth/reset-password")
            .then()
            .statusCode(OK.getStatusCode());

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

    private AuthenticationResponse signIn(final String email, final String password) {
        final Response response = given()
            .contentType("application/json")
            .body(SignIn.builder().email(email).password(password).build())
            .when()
            .post("/auth/sign-in")
            .then()
            .statusCode(OK.getStatusCode())
            .extract().response();

        return response.getBody().as(AuthenticationResponse.class);
    }
}