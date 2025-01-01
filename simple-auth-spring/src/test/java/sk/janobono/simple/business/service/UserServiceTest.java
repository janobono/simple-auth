package sk.janobono.simple.business.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import sk.janobono.simple.BaseTest;
import sk.janobono.simple.InitDataCommandLineRunner;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.api.model.User;
import sk.janobono.simple.api.model.UserCreate;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.common.exception.ApplicationException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UserServiceTest extends BaseTest {

    @Autowired
    public CommonConfigProperties commonConfigProperties;

    @Autowired
    public InitDataCommandLineRunner initDataCommandLineRunner;

    @Autowired
    public UserService userService;

    @Test
    void addUser_whenExistingEmail_thenException() {
        // GIVEN
        userRepository.deleteAll();
        initDataCommandLineRunner.run();

        final UserCreate userCreate = UserCreate.builder()
                .email(commonConfigProperties.mail())
                .build();

        // THEN
        Assertions.assertThrows(
                ApplicationException.class,
                () -> userService.addUser(userCreate)
        );
    }

    @Test
    void addUser_whenValidInput_thenResult() {
        // GIVEN
        final UserCreate userCreate = UserCreate.builder()
                .email("test@test.sk")
                .firstName("first")
                .lastName("last")
                .confirmed(true)
                .enabled(true)
                .authorities(List.of(Authority.CUSTOMER))
                .build();

        // WHEN
        final User user = userService.addUser(userCreate);

        // THEN
        assertThat(user).isNotNull();
        assertThat(user.getId()).isNotNull();
        assertThat(user.getEmail()).isEqualTo(userCreate.getEmail());
        assertThat(user.getFirstName()).isEqualTo(userCreate.getFirstName());
        assertThat(user.getLastName()).isEqualTo(userCreate.getLastName());
        assertThat(user.getAuthorities()).isEqualTo(userCreate.getAuthorities());
    }

    @Test
    void getUser_whenDefaultUser_thenResult() {
        // WHEN
        userRepository.deleteAll();
        initDataCommandLineRunner.run();
        final Long id = userRepository.getUserDo(commonConfigProperties.mail()).getId();

        // WHEN
        final User user = userService.getUser(id);

        // THEN
        assertThat(user).isNotNull();
        assertThat(user.getId()).isEqualTo(id);
        assertThat(user.getEmail()).isEqualTo(commonConfigProperties.mail());
    }

    @Test
    void deleteUser_whenNotExists_thenException() {
        Assertions.assertThrows(
                ApplicationException.class,
                () -> userService.deleteUser(10000L)
        );
    }
}
