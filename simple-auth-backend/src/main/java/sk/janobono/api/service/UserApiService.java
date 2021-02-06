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
import sk.janobono.api.service.so.RoleDetailSO;
import sk.janobono.api.service.so.RoleSO;
import sk.janobono.api.service.so.UserDetailSO;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.dal.domain.Role;
import sk.janobono.dal.domain.User;
import sk.janobono.dal.repository.RoleRepository;
import sk.janobono.dal.repository.UserRepository;
import sk.janobono.dal.specification.UserSpecification;
import sk.janobono.mapper.RoleMapper;
import sk.janobono.mapper.UserMapper;

import java.util.Comparator;

@Service
public class UserApiService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserApiService.class);

    private PasswordEncoder passwordEncoder;

    private RoleMapper roleMapper;

    private UserMapper userMapper;

    private UserRepository userRepository;

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Autowired
    public void setRoleMapper(RoleMapper roleMapper) {
        this.roleMapper = roleMapper;
    }

    @Autowired
    public void setUserMapper(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Page<UserDetailSO> getUsers(Pageable pageable) {
        LOGGER.debug("getUsers({})", pageable);
        return userRepository.findAll(pageable).map(this::mapUser);
    }

    public Page<UserDetailSO> getUsers(String searchField, Pageable pageable) {
        LOGGER.debug("getUsers({},{})", searchField, pageable);
        return userRepository.findAll(new UserSpecification(searchField), pageable).map(this::mapUser);
    }

    public UserDetailSO getUser(Long id) {
        LOGGER.debug("getUser({})", id);
        return userRepository.findById(id)
                .map(this::mapUser)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found!"));
    }

    @Transactional
    public UserDetailSO addUser(UserSO userSO) {
        LOGGER.debug("addUser({})", userSO);
        userSO.setUsername(userSO.getUsername().toLowerCase());
        userSO.setPassword(passwordEncoder.encode(userSO.getPassword()));
        if (userRepository.existsByUsername(userSO.getUsername())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is already taken!");
        }
        User user = userMapper.userSOToUser(userSO);
        user = userRepository.save(user);
        LOGGER.debug("addUser({})={}", userSO, user);
        return mapUser(user);
    }

    @Transactional
    public UserDetailSO setUser(Long id, UserSO userSO) {
        LOGGER.debug("setUser({})", userSO);
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found!"));

        userSO.setUsername(userSO.getUsername().toLowerCase());
        if (userRepository.existsByUsernameAndIdNot(userSO.getUsername(), id)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is already taken!");
        }
        user.setUsername(userSO.getUsername());
        if (!passwordEncoder.matches(userSO.getPassword(), user.getPassword())) {
            user.setPassword(passwordEncoder.encode(userSO.getPassword()));
        }
        user.setEnabled(userSO.getEnabled());
        user.getRoles().clear();
        for (RoleDetailSO roleDetailSO : userSO.getRoles()) {
            user.getRoles().add(roleMapper.roleDetailSOToRole(roleDetailSO));
        }
        user.getAttributes().clear();
        user.setAttributes(userSO.getAttributes());
        user = userRepository.save(user);
        LOGGER.debug("setUser({})={}", userSO, user);
        return mapUser(user);
    }

    @Transactional
    public void deleteUser(Long id) {
        LOGGER.debug("deleteUser({})", id);
        if (!userRepository.existsById(id)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found!");
        }
        userRepository.deleteById(id);
    }

    private UserDetailSO mapUser(User user) {
        UserDetailSO result = userMapper.userToUserDetailSO(user);
        result.getRoles().sort(Comparator.comparing(RoleDetailSO::getId));
        LOGGER.debug("mapUser({})={}", user, result);
        return result;
    }
}
