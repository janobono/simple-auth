package sk.janobono.simple.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import sk.janobono.simple.BaseTest;
import sk.janobono.simple.InitDataCommandLineRunner;
import sk.janobono.simple.api.model.*;
import sk.janobono.simple.common.config.CommonConfigProperties;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class UserControllerTest extends BaseTest {

    @Autowired
    public CommonConfigProperties commonConfigProperties;

    @Autowired
    public InitDataCommandLineRunner initDataCommandLineRunner;

    @Test
    public void allUserControllerMethods() {
        userRepository.deleteAll();
        initDataCommandLineRunner.run();

        final AuthenticationResponse authenticationResponse = signIn(commonConfigProperties.mail(), "simple");

        final List<User> users = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            users.add(addUser(authenticationResponse, i));
        }

        for (final User user : users) {
            assertThat(user).usingRecursiveComparison().isEqualTo(getUser(authenticationResponse, user.getId()));
        }

        PageUser page = getUsers(authenticationResponse, null, null, Pageable.unpaged());
        assertThat(page.getTotalElements()).isEqualTo(11);
        assertThat(page.getTotalPages()).isEqualTo(1);
        assertThat(page.getContent()).hasSize(11);

        page = getUsers(authenticationResponse, "first irst rst st", null, Pageable.unpaged());
        assertThat(page.getTotalElements()).isEqualTo(10);
        assertThat(page.getTotalPages()).isEqualTo(1);
        assertThat(page.getContent()).hasSize(10);

        page = getUsers(authenticationResponse, null, "mail1@domain.com", Pageable.unpaged());
        assertThat(page.getTotalElements()).isEqualTo(1);
        assertThat(page.getTotalPages()).isEqualTo(1);
        assertThat(page.getContent()).hasSize(1);

        for (final User user : users) {
            setUser(authenticationResponse, user);
            setAuthorities(authenticationResponse, user.getId());
            setConfirmed(authenticationResponse, user.getId());
            setEnabled(authenticationResponse, user.getId());
            deleteUser(authenticationResponse, user.getId());
        }

        page = getUsers(authenticationResponse, null, null, Pageable.unpaged());
        assertThat(page.getTotalElements()).isEqualTo(1);
        assertThat(page.getTotalPages()).isEqualTo(1);
        assertThat(page.getContent()).hasSize(1);
    }

    private User getUser(final AuthenticationResponse authenticationResponse, final Long id) {
        return restClient.get()
                .uri(getURI("/users/{id}", Map.of("id", id.toString())))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .retrieve()
                .body(User.class);
    }

    private PageUser getUsers(final AuthenticationResponse authenticationResponse,
                              final String searchField,
                              final String email,
                              final Pageable pageable) {
        final LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        addToParams(params, "searchField", searchField);
        addToParams(params, "email", email);
        addPageableToParams(params, pageable);
        return restClient.get()
                .uri(getURI("/users", params))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .retrieve()
                .body(PageUser.class);
    }

    private User addUser(final AuthenticationResponse authenticationResponse, final int index) {
        return restClient.post()
                .uri(getURI("/users"))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(UserCreate.builder()
                        .email("mail" + index + "@domain.com")
                        .firstName("First" + index)
                        .lastName("Last" + index)
                        .confirmed(false)
                        .enabled(false)
                        .authorities(List.of(Authority.CUSTOMER))
                        .build())
                .retrieve()
                .body(User.class);
    }

    private void setUser(final AuthenticationResponse authenticationResponse, final User user) {
        final ResponseEntity<User> response = restClient.put()
                .uri(getURI("/users/{id}", Map.of("id", user.getId().toString())))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(UserProfile.builder()
                        .firstName(user.getFirstName() + "changed")
                        .lastName(user.getLastName() + "changed")
                        .build())
                .retrieve()
                .toEntity(User.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getFirstName()).endsWith("changed");
        assertThat(response.getBody().getLastName()).endsWith("changed");
    }

    private void setAuthorities(final AuthenticationResponse authenticationResponse, final Long id) {
        final ResponseEntity<User> response = restClient.patch()
                .uri(getURI("/users/{id}/authorities", Map.of("id", id.toString())))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(List.of(Authority.CUSTOMER, Authority.EMPLOYEE))
                .retrieve()
                .toEntity(User.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getAuthorities()).hasSize(2);
    }

    private void setConfirmed(final AuthenticationResponse authenticationResponse, final Long id) {
        final ResponseEntity<User> response = restClient.patch()
                .uri(getURI("/users/{id}/confirm", Map.of("id", id.toString())))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(BooleanValue.builder().value(true).build())
                .retrieve()
                .toEntity(User.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getConfirmed()).isTrue();
    }

    private void setEnabled(final AuthenticationResponse authenticationResponse, final Long id) {
        final ResponseEntity<User> response = restClient.patch()
                .uri(getURI("/users/{id}/enable", Map.of("id", id.toString())))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .body(BooleanValue.builder().value(true).build())
                .retrieve()
                .toEntity(User.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getEnabled()).isTrue();
    }

    private void deleteUser(final AuthenticationResponse authenticationResponse, final Long id) {
        restClient.delete()
                .uri(getURI("/users/{id}", Map.of("id", id.toString())))
                .header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
                .retrieve();
    }
}
