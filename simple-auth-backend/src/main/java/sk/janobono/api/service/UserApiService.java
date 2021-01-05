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
import sk.janobono.api.service.so.RoleSO;
import sk.janobono.api.service.so.UserDetailSO;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.dal.domain.Role;
import sk.janobono.dal.domain.User;
import sk.janobono.dal.repository.RoleRepository;
import sk.janobono.dal.repository.UserRepository;
import sk.janobono.dal.specification.UserSpecification;
import sk.janobono.mapper.UserMapper;

@Service
public class UserApiService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserApiService.class);

    private PasswordEncoder passwordEncoder;

    private UserMapper userMapper;

    private RoleRepository roleRepository;

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
    public void setRoleRepository(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Autowired
    public void setUserRepository(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Page<UserDetailSO> getUsers(Pageable pageable) {
        LOGGER.debug("getUsers({})", pageable);
        return userRepository.findAll(pageable).map(userMapper::userToUserDetailSO);
    }

    public Page<UserDetailSO> getUsers(String searchField, Pageable pageable) {
        LOGGER.debug("getUsers({},{})", searchField, pageable);
        return userRepository.findAll(new UserSpecification(searchField), pageable).map(userMapper::userToUserDetailSO);
    }

    public UserDetailSO getUser(Long id) {
        LOGGER.debug("getUser({})", id);
        return userRepository.findById(id)
                .map(userMapper::userToUserDetailSO)
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
        resetRoles(user, userSO);
        user = userRepository.save(user);
        LOGGER.debug("addUser({})={}", userSO, user);
        return userMapper.userToUserDetailSO(user);
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
        resetRoles(user, userSO);
        user.getAttributes().clear();
        user.setAttributes(userSO.getAttributes());
        user = userRepository.save(user);
        LOGGER.debug("setUser({})={}", userSO, user);
        return userMapper.userToUserDetailSO(user);
    }

    private void resetRoles(User user, UserSO userSO) {
        user.getRoles().clear();
        for (RoleSO roleSO : userSO.getRoles()) {
            Role role = roleRepository.findByName(roleSO.getName())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Role not found!"));
            user.getRoles().add(role);
        }
    }

    @Transactional
    public void deleteUser(Long id) {
        LOGGER.debug("deleteUser({})", id);
        if (!userRepository.existsById(id)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found!");
        }
        userRepository.deleteById(id);
    }
}
