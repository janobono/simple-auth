package sk.janobono.api.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;
import sk.janobono.api.service.so.UserCreateSO;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.api.service.so.UserUpdateSO;
import sk.janobono.component.UserComponent;
import sk.janobono.dal.domain.Authority;
import sk.janobono.dal.domain.User;
import sk.janobono.dal.repository.UserRepository;
import sk.janobono.dal.specification.UserSpecification;

@Service
public class UserApiService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserApiService.class);

    private PasswordEncoder passwordEncoder;

    private UserComponent userComponent;

    private UserRepository userRepository;

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Autowired
    public void setUserComponent(UserComponent userComponent) {
        this.userComponent = userComponent;
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Page<UserSO> getUsers(Pageable pageable) {
        LOGGER.debug("getUsers({})", pageable);
        Page<UserSO> result = userRepository.findAll(pageable).map(userComponent::toUserSO);
        LOGGER.debug("getUsers({})={}", pageable, result);
        return result;
    }

    public Page<UserSO> getUsers(String searchField, Pageable pageable) {
        LOGGER.debug("getUsers({},{})", searchField, pageable);
        Page<UserSO> result = userRepository.findAll(new UserSpecification(searchField), pageable).map(userComponent::toUserSO);
        LOGGER.debug("getUsers({},{})={}", searchField, pageable, result);
        return result;
    }

    public UserSO getUser(Long id) {
        LOGGER.debug("getUser({})", id);
        User user = userRepository.findById(id).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found.")
        );
        UserSO result = userComponent.toUserSO(user);
        LOGGER.debug("getUser({})={}", id, result);
        return result;
    }

    @Transactional
    public UserSO addUser(UserCreateSO userCreateSO) {
        LOGGER.debug("addUser({})", userCreateSO);
        if (userRepository.existsByUsername(userCreateSO.username().toLowerCase())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is already taken.");
        }
        User user = new User();
        user.setUsername(userCreateSO.username());
        user.setPassword(passwordEncoder.encode(userCreateSO.password()));
        user.setEnabled(userCreateSO.enabled());
        user.getAuthorities().addAll(
                userCreateSO.authorities().stream()
                        .map(a -> new Authority(a.id(), a.name())).toList()
        );
        user.getAttributes().putAll(userCreateSO.attributes());
        user = userRepository.save(user);
        UserSO result = userComponent.toUserSO(user);
        LOGGER.debug("addUser({})={}", userCreateSO, result);
        return result;
    }

    @Transactional
    public UserSO setUser(Long id, UserUpdateSO userUpdateSO) {
        LOGGER.debug("setUser({},{})", id, userUpdateSO);
        if (userRepository.existsByUsernameAndIdNot(userUpdateSO.username().toLowerCase(), id)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is already taken.");
        }
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found."));
        user.setUsername(userUpdateSO.username());
        if (StringUtils.hasLength(userUpdateSO.password())) {
            user.setPassword(passwordEncoder.encode(userUpdateSO.password()));
        }
        user.setEnabled(userUpdateSO.enabled());
        user.getAuthorities().clear();
        user.getAuthorities().addAll(
                userUpdateSO.authorities().stream()
                        .map(a -> new Authority(a.id(), a.name())).toList()
        );
        user.getAttributes().clear();
        user.setAttributes(userUpdateSO.attributes());
        user = userRepository.save(user);
        UserSO result = userComponent.toUserSO(user);
        LOGGER.debug("setUser({},{})={}", id, userUpdateSO, result);
        return result;
    }

    @Transactional
    public void deleteUser(Long id) {
        LOGGER.debug("deleteUser({})", id);
        if (!userRepository.existsById(id)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found.");
        }
        userRepository.deleteById(id);
    }
}
