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
import org.springframework.web.server.ResponseStatusException;
import sk.janobono.api.service.so.UserCreateSO;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.api.service.so.UserUpdateSO;
import sk.janobono.dal.domain.Authority;
import sk.janobono.dal.domain.User;
import sk.janobono.dal.repository.UserRepository;
import sk.janobono.dal.specification.UserSpecification;
import sk.janobono.mapper.UserMapper;

import java.util.stream.Collectors;

@Service
public class UserApiService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserApiService.class);

    private PasswordEncoder passwordEncoder;

    private UserMapper userMapper;

    private UserRepository userRepository;

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Autowired
    public void setUserMapper(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Page<UserSO> getUsers(Pageable pageable) {
        LOGGER.debug("getUsers({})", pageable);
        Page<UserSO> result = userRepository.findAll(pageable).map(userMapper::userToUserSO);
        LOGGER.debug("getUsers({})={}", pageable, result);
        return result;
    }

    public Page<UserSO> getUsers(String searchField, Pageable pageable) {
        LOGGER.debug("getUsers({},{})", searchField, pageable);
        Page<UserSO> result = userRepository.findAll(new UserSpecification(searchField), pageable).map(userMapper::userToUserSO);
        LOGGER.debug("getUsers({},{})={}", searchField, pageable, result);
        return result;
    }

    public UserSO getUser(Long id) {
        LOGGER.debug("getUser({})", id);
        User user = userRepository.findById(id).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found.")
        );
        UserSO result = userMapper.userToUserSO(user);
        LOGGER.debug("getUser({})={}", id, result);
        return result;
    }

    @Transactional
    public UserSO addUser(UserCreateSO userCreateSO) {
        LOGGER.debug("addUser({})", userCreateSO);
        if (userRepository.existsByUsername(userCreateSO.getUsername().toLowerCase())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is already taken.");
        }
        User user = new User();
        user.setUsername(userCreateSO.getUsername());
        user.setPassword(passwordEncoder.encode(userCreateSO.getPassword()));
        user.setEnabled(userCreateSO.getEnabled());
        user.getAuthorities().addAll(
                userCreateSO.getAuthorities().stream()
                        .map(a -> new Authority(a.getId(), a.getName())).collect(Collectors.toList())
        );
        user.getAttributes().putAll(userCreateSO.getAttributes());
        user = userRepository.save(user);
        UserSO result = userMapper.userToUserSO(user);
        LOGGER.debug("addUser({})={}", userCreateSO, result);
        return result;
    }

    @Transactional
    public UserSO setUser(Long id, UserUpdateSO userUpdateSO) {
        LOGGER.debug("setUser({},{})", id, userUpdateSO);
        if (userRepository.existsByUsernameAndIdNot(userUpdateSO.getUsername().toLowerCase(), id)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is already taken.");
        }
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found."));
        user.setUsername(userUpdateSO.getUsername());
        if (!passwordEncoder.matches(userUpdateSO.getPassword(), user.getPassword())) {
            user.setPassword(passwordEncoder.encode(userUpdateSO.getPassword()));
        }
        user.setEnabled(userUpdateSO.getEnabled());
        user.getAuthorities().clear();
        user.getAuthorities().addAll(
                userUpdateSO.getAuthorities().stream()
                        .map(a -> new Authority(a.getId(), a.getName())).collect(Collectors.toList())
        );
        user.getAttributes().clear();
        user.setAttributes(userUpdateSO.getAttributes());
        user = userRepository.save(user);
        UserSO result = userMapper.userToUserSO(user);
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
