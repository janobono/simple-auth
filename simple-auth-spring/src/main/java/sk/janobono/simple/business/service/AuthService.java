package sk.janobono.simple.business.service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import sk.janobono.simple.api.model.AuthenticationResponse;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.api.model.ChangeEmail;
import sk.janobono.simple.api.model.ChangePassword;
import sk.janobono.simple.api.model.ChangeUserDetails;
import sk.janobono.simple.api.model.Confirmation;
import sk.janobono.simple.api.model.ResetPassword;
import sk.janobono.simple.api.model.SignIn;
import sk.janobono.simple.api.model.SignUp;
import sk.janobono.simple.api.model.User;
import sk.janobono.simple.business.model.mail.MailContentData;
import sk.janobono.simple.business.model.mail.MailData;
import sk.janobono.simple.business.model.mail.MailLinkData;
import sk.janobono.simple.common.component.CaptchaUtil;
import sk.janobono.simple.common.component.JwtToken;
import sk.janobono.simple.common.component.ScDf;
import sk.janobono.simple.common.component.VerificationToken;
import sk.janobono.simple.common.config.AuthConfigProperties;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.common.exception.SimpleAuthServiceException;
import sk.janobono.simple.dal.domain.AuthorityDo;
import sk.janobono.simple.dal.domain.UserDo;
import sk.janobono.simple.dal.repository.AuthorityRepository;
import sk.janobono.simple.dal.repository.UserRepository;

@RequiredArgsConstructor
@Service
public class AuthService {

    private static final String CONFIRM_USER = "CONFIRM_USER";
    private static final String RESET_PASSWORD = "RESET_PASSWORD";
    private static final String TYPE = "TYPE";
    private static final String ID = "ID";
    private static final String NEW_PASSWORD = "NEW_PASSWORD";

    private final AuthConfigProperties authConfigProperties;
    private final CommonConfigProperties commonConfigProperties;

    private final CaptchaUtil captchaUtil;
    private final JwtToken jwtToken;
    private final PasswordEncoder passwordEncoder;
    private final ScDf scDf;
    private final VerificationToken verificationToken;

    private final MailService mailService;

    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;

    @Transactional
    public AuthenticationResponse changeEmail(final ChangeEmail changeEmail) {
        final User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        captchaUtil.checkTokenValid(changeEmail.getCaptchaText(), changeEmail.getCaptchaToken());
        if (userRepository.existsByEmail(scDf.toStripAndLowerCase(changeEmail.getEmail()))) {
            throw SimpleAuthServiceException.USER_EMAIL_IS_USED.exception("Email is used");
        }
        final UserDo userDo = userRepository.getUserDo(user.getId());
        checkEnabled(userDo);
        checkPassword(userDo, changeEmail.getPassword());
        userDo.setEmail(scDf.toStripAndLowerCase(changeEmail.getEmail()));
        return createAuthenticationResponse(userRepository.save(userDo));
    }

    @Transactional
    public AuthenticationResponse changePassword(final ChangePassword changePassword) {
        final User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        captchaUtil.checkTokenValid(changePassword.getCaptchaText(), changePassword.getCaptchaToken());
        final UserDo userDo = userRepository.getUserDo(user.getId());
        checkEnabled(userDo);
        checkPassword(userDo, changePassword.getOldPassword());
        userDo.setPassword(passwordEncoder.encode(changePassword.getNewPassword()));
        return createAuthenticationResponse(userRepository.save(userDo));
    }

    @Transactional
    public AuthenticationResponse changeUserDetails(final ChangeUserDetails changeUserDetails) {
        final User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        captchaUtil.checkTokenValid(changeUserDetails.getCaptchaText(), changeUserDetails.getCaptchaToken());
        final UserDo userDo = userRepository.getUserDo(user.getId());
        checkEnabled(userDo);

        userDo.setFirstName(changeUserDetails.getFirstName());
        userDo.setLastName(changeUserDetails.getLastName());

        return createAuthenticationResponse(userRepository.save(userDo));
    }

    @Transactional
    public AuthenticationResponse confirm(final Confirmation confirmation) {
        final Map<String, String> data = verificationToken.parseToken(confirmation.getToken());
        final UserDo userDo = switch (data.get(TYPE)) {
            case CONFIRM_USER -> confirmUser(Long.valueOf(data.get(ID)));
            case RESET_PASSWORD -> resetPassword(Long.valueOf(data.get(ID)), data.get(NEW_PASSWORD));
            default -> throw SimpleAuthServiceException.UNSUPPORTED_VALIDATION_TOKEN.exception("Unsupported token");
        };
        return createAuthenticationResponse(userDo);
    }

    public User getUserDetail() {
        return (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

    @Transactional(readOnly = true)
    public void resetPassword(final ResetPassword resetPassword) {
        captchaUtil.checkTokenValid(resetPassword.getCaptchaText(), resetPassword.getCaptchaToken());
        final UserDo userDo = userRepository.findByEmail(scDf.toStripAndLowerCase(resetPassword.getEmail())).orElseThrow(
            () -> SimpleAuthServiceException.USER_NOT_FOUND.exception("User with email {0} not found", resetPassword.getEmail())
        );
        checkConfirmed(userDo);
        checkEnabled(userDo);
        sendResetPasswordMail(userDo);
    }

    @Transactional(readOnly = true)
    public AuthenticationResponse signIn(final SignIn signIn) {
        final UserDo userDo = userRepository.findByEmail(scDf.toStripAndLowerCase(signIn.getEmail())).orElseThrow(
            () -> SimpleAuthServiceException.USER_NOT_FOUND.exception("User with email {0} not found", signIn.getEmail())
        );
        checkConfirmed(userDo);
        checkEnabled(userDo);
        checkPassword(userDo, signIn.getPassword());
        return createAuthenticationResponse(userDo);
    }

    @Transactional
    public AuthenticationResponse signUp(final SignUp signUp) {
        captchaUtil.checkTokenValid(signUp.getCaptchaText(), signUp.getCaptchaToken());
        if (userRepository.existsByEmail(scDf.toStripAndLowerCase(signUp.getEmail()))) {
            throw SimpleAuthServiceException.USER_EMAIL_IS_USED.exception("Email is used");
        }
        final UserDo userDo = userRepository.save(UserDo.builder()
            .email(scDf.toStripAndLowerCase(signUp.getEmail()))
            .password(passwordEncoder.encode(signUp.getPassword()))
            .firstName(signUp.getFirstName())
            .lastName(signUp.getLastName())
            .confirmed(false)
            .enabled(true)
            .build()
        );

        sendSignUpMail(userDo);
        return createAuthenticationResponse(userDo);
    }

    private void checkConfirmed(final UserDo userDo) {
        if (!userDo.isConfirmed()) {
            throw SimpleAuthServiceException.USER_NOT_CONFIRMED.exception("User is not confirmed");
        }
    }

    private void checkEnabled(final UserDo userDo) {
        if (!userDo.isEnabled()) {
            throw SimpleAuthServiceException.USER_IS_DISABLED.exception("User is disabled");
        }
    }

    private void checkPassword(final UserDo userDo, final String password) {
        if (!passwordEncoder.matches(password, userDo.getPassword())) {
            throw SimpleAuthServiceException.INVALID_CREDENTIALS.exception("Invalid credentials");
        }
    }

    private AuthenticationResponse createAuthenticationResponse(final UserDo user) {
        final Long issuedAt = System.currentTimeMillis();
        return AuthenticationResponse.builder()
            .token(jwtToken.generateToken(
                new JwtToken.JwtContent(
                    user.getId(),
                    user.getAuthorities().stream()
                        .map(AuthorityDo::getAuthority)
                        .toList()), issuedAt)
            )
            .type("Bearer")
            .build();
    }

    private UserDo confirmUser(final Long userId) {
        final UserDo userDo = userRepository.getUserDo(userId);
        checkEnabled(userDo);
        userDo.setConfirmed(true);
        userDo.getAuthorities().add(authorityRepository.getAuthorityDo(Authority.CUSTOMER));
        return userRepository.save(userDo);
    }

    private UserDo resetPassword(final Long userId, final String newPassword) {
        final UserDo userDo = userRepository.getUserDo(userId);
        checkEnabled(userDo);
        userDo.setPassword(passwordEncoder.encode(newPassword));
        return userRepository.save(userDo);
    }

    private void sendResetPasswordMail(final UserDo user) {
        final Map<String, String> data = new HashMap<>();
        data.put(TYPE, RESET_PASSWORD);
        data.put(ID, user.getId().toString());
        data.put(NEW_PASSWORD, RandomStringUtils.secure().nextAlphanumeric(10));
        final long issuedAt = System.currentTimeMillis();
        final String token = verificationToken.generateToken(
            data,
            issuedAt,
            issuedAt + TimeUnit.MINUTES.toMillis(authConfigProperties.resetPasswordTokenExpiration())
        );

        mailService.sendEmail(MailData.builder()
            .from(commonConfigProperties.mail())
            .recipients(List.of(user.getEmail()))
            .subject("Password reset")
            .content(MailContentData.builder()
                .title("Password reset")
                .lines(List.of(
                        "New password was generated",
                        "password: %s".formatted(data.get(NEW_PASSWORD))
                    )
                )
                .mailLink(MailLinkData.builder()
                    .href(getTokenUrl(commonConfigProperties.webUrl(), commonConfigProperties.confirmPath(), token))
                    .text("Click to confirm")
                    .build())
                .build())
            .build());
    }

    private void sendSignUpMail(final UserDo user) {
        final Map<String, String> data = new HashMap<>();
        data.put(TYPE, CONFIRM_USER);
        data.put(ID, user.getId().toString());
        final long issuedAt = System.currentTimeMillis();
        final String token = verificationToken.generateToken(
            data,
            issuedAt,
            issuedAt + TimeUnit.MINUTES.toMillis(authConfigProperties.signUpTokenExpiration())
        );

        mailService.sendEmail(MailData.builder()
            .from(commonConfigProperties.mail())
            .recipients(List.of(user.getEmail()))
            .subject("Sign up")
            .content(MailContentData.builder()
                .title("Sign up")
                .lines(List.of("New account created"))
                .mailLink(MailLinkData.builder()
                    .href(getTokenUrl(commonConfigProperties.webUrl(), commonConfigProperties.confirmPath(), token))
                    .text("Click to confirm")
                    .build())
                .build())
            .build());
    }

    private String getTokenUrl(final String webUrl, final String path, final String token) {
        try {
            return webUrl + path + URLEncoder.encode(token, StandardCharsets.UTF_8);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }
}
