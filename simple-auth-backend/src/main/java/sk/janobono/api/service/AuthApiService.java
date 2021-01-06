package sk.janobono.api.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import sk.janobono.api.service.so.*;
import sk.janobono.component.JwtToken;
import sk.janobono.dal.domain.Role;
import sk.janobono.dal.domain.User;
import sk.janobono.dal.repository.RoleRepository;
import sk.janobono.dal.repository.UserRepository;
import sk.janobono.mapper.RoleMapper;

import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class AuthApiService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthApiService.class);

    private PasswordEncoder passwordEncoder;

    private JwtToken jwtToken;

    private RoleMapper roleMapper;

    private RoleRepository roleRepository;

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
    public void setRoleMapper(RoleMapper roleMapper) {
        this.roleMapper = roleMapper;
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Autowired
    public void setRoleRepository(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
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

        JwtToken.JwtUser jwtUser = new JwtToken.JwtUser();
        jwtUser.setId(user.getId());
        jwtUser.setUsername(user.getUsername());
        jwtUser.setEnabled(user.getEnabled());
        jwtUser.setRoles(user.getRoles().stream().map(Role::getName).collect(Collectors.toSet()));
        jwtUser.setAttributes(user.getAttributes());

        AuthenticationResponseSO authenticationResponse = new AuthenticationResponseSO();
        Long issuedAt = System.currentTimeMillis();
        authenticationResponse.setToken(jwtToken.generateToken(jwtUser, issuedAt));
        authenticationResponse.setExpiresAt(jwtToken.expiresAt(issuedAt));
        LOGGER.info("authenticate({}) - {}", authenticationRequestSO, authenticationResponse);
        return authenticationResponse;
    }

    public UserDetailSO getCurrentUser() {
        LOGGER.debug("getCurrentUser()");
        JwtToken.JwtUser jwtUser = (JwtToken.JwtUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        UserDetailSO user = new UserDetailSO();
        user.setId(jwtUser.getId());
        user.setUsername(jwtUser.getUsername());
        user.setEnabled(jwtUser.getEnabled());
        for (String roleName : jwtUser.getRoles()) {
            Optional<Role> optionalRole = roleRepository.findByName(roleName);
            optionalRole.ifPresent(role -> user.getRoles().add(roleMapper.roleToRoleDetailSO(role)));
        }
        user.setAttributes(jwtUser.getAttributes());
        return user;
    }
}
