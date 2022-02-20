package sk.janobono.api.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import sk.janobono.api.service.so.AuthenticationRequestSO;
import sk.janobono.api.service.so.AuthenticationResponseSO;
import sk.janobono.component.JwtToken;
import sk.janobono.dal.domain.User;
import sk.janobono.dal.repository.UserRepository;

@Service
public class AuthApiService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthApiService.class);

    private PasswordEncoder passwordEncoder;

    private JwtToken jwtToken;

    private UserRepository userRepository;

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Autowired
    public void setJwtToken(JwtToken jwtToken) {
        this.jwtToken = jwtToken;
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public AuthenticationResponseSO authenticate(AuthenticationRequestSO authenticationRequestSO) {
        LOGGER.debug("authenticate({})", authenticationRequestSO);

        User user = userRepository.findByUsername(authenticationRequestSO.username().toLowerCase())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found."));

        if (!user.getEnabled()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User disabled.");
        }

        if (!passwordEncoder.matches(authenticationRequestSO.password(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid credentials.");
        }

        Long issuedAt = System.currentTimeMillis();
        AuthenticationResponseSO authenticationResponse = new AuthenticationResponseSO(
                jwtToken.generateToken(user, issuedAt)
        );
        LOGGER.info("authenticate({}) - {}", authenticationRequestSO, authenticationResponse);
        return authenticationResponse;
    }
}
