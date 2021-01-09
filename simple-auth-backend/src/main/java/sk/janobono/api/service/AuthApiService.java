package sk.janobono.api.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import sk.janobono.api.service.so.AuthenticationRequestSO;
import sk.janobono.api.service.so.AuthenticationResponseSO;
import sk.janobono.api.service.so.UserDetailSO;
import sk.janobono.component.JwtToken;
import sk.janobono.dal.domain.User;
import sk.janobono.dal.repository.UserRepository;
import sk.janobono.mapper.UserMapper;

@Service
public class AuthApiService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthApiService.class);

    private PasswordEncoder passwordEncoder;

    private JwtToken jwtToken;

    private UserMapper userMapper;

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
    public void setUserMapper(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public AuthenticationResponseSO authenticate(AuthenticationRequestSO authenticationRequestSO) {
        LOGGER.debug("authenticate({})", authenticationRequestSO);

        User user = userRepository.findByUsername(authenticationRequestSO.getUsername().toLowerCase())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found!"));

        if (!user.getEnabled()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User disabled!");
        }

        if (!passwordEncoder.matches(authenticationRequestSO.getPassword(), user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid credentials!");
        }

        AuthenticationResponseSO authenticationResponse = new AuthenticationResponseSO();
        Long issuedAt = System.currentTimeMillis();
        authenticationResponse.setToken(jwtToken.generateToken(user, issuedAt));
        authenticationResponse.setExpiresAt(jwtToken.expiresAt(issuedAt));
        LOGGER.info("authenticate({}) - {}", authenticationRequestSO, authenticationResponse);
        return authenticationResponse;
    }

    public UserDetailSO getCurrentUser() {
        LOGGER.debug("getCurrentUser()");
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        LOGGER.debug("getCurrentUser() = {}", user);
        return userMapper.userToUserDetailSO(user);
    }
}
