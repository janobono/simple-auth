package sk.janobono.simple.api;

import static io.restassured.RestAssured.given;
import static jakarta.ws.rs.core.Response.Status.CREATED;
import static jakarta.ws.rs.core.Response.Status.OK;
import static org.assertj.core.api.Assertions.assertThat;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sk.janobono.simple.InitDataCommandLineRunner;
import sk.janobono.simple.api.model.AuthenticationResponse;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.api.model.BooleanValue;
import sk.janobono.simple.api.model.PageUser;
import sk.janobono.simple.api.model.SignIn;
import sk.janobono.simple.api.model.User;
import sk.janobono.simple.api.model.UserCreate;
import sk.janobono.simple.api.model.UserProfile;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.dal.repository.UserRepository;

@QuarkusTest
class UserControllerTest {

  @Inject
  public CommonConfigProperties commonConfigProperties;

  @Inject
  public InitDataCommandLineRunner initDataCommandLineRunner;

  @Inject
  public UserRepository userRepository;

  @Transactional
  @BeforeEach
  public void setUp() {
    userRepository.deleteAll();
    initDataCommandLineRunner.initAuthorities();
    initDataCommandLineRunner.initUsers();
  }

  @Test
  void allUserControllerMethods() {
    final AuthenticationResponse authenticationResponse = signIn();

    final List<User> users = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      users.add(addUser(authenticationResponse, i));
    }

    for (final User user : users) {
      assertThat(user).usingRecursiveComparison()
          .isEqualTo(getUser(authenticationResponse, user.getId()));
    }

    PageUser page = getUsers(authenticationResponse, null, null);
    assertThat(page.getTotalElements()).isEqualTo(11);
    assertThat(page.getTotalPages()).isEqualTo(1);
    assertThat(page.getContent()).hasSize(11);

    page = getUsers(authenticationResponse, "first irst rst st", null);
    assertThat(page.getTotalElements()).isEqualTo(10);
    assertThat(page.getTotalPages()).isEqualTo(1);
    assertThat(page.getContent()).hasSize(10);

    page = getUsers(authenticationResponse, null, "mail1@domain.com");
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

    page = getUsers(authenticationResponse, null, null);
    assertThat(page.getTotalElements()).isEqualTo(1);
    assertThat(page.getTotalPages()).isEqualTo(1);
    assertThat(page.getContent()).hasSize(1);
  }

  private User getUser(final AuthenticationResponse authenticationResponse, final Long id) {
    final Response response = given()
        .header("Authorization", "Bearer " + authenticationResponse.getToken())
        .contentType("application/json")
        .when()
        .get("/users/%d".formatted(id))
        .then()
        .statusCode(OK.getStatusCode())
        .extract().response();

    return response.getBody().as(User.class);
  }

  private PageUser getUsers(final AuthenticationResponse authenticationResponse,
      final String searchField,
      final String email) {
    final StringBuilder path = new StringBuilder("/users");

    if (searchField != null || email != null) {
      path.append("?");
    }

    if (searchField != null) {
      path.append("searchField=").append(searchField);
    }

    if (email != null) {
      if (searchField != null) {
        path.append("&");
      }
      path.append("email=").append(email);
    }

    final Response response = given()
        .header("Authorization", "Bearer " + authenticationResponse.getToken())
        .contentType("application/json")
        .when()
        .get(path.toString())
        .then()
        .statusCode(OK.getStatusCode())
        .extract().response();

    return response.getBody().as(PageUser.class);
  }

  private User addUser(final AuthenticationResponse authenticationResponse, final int index) {
    final Response response = given()
        .contentType("application/json")
        .header("Authorization",
            "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
        .body(UserCreate.builder()
            .email("mail" + index + "@domain.com")
            .firstName("First" + index)
            .lastName("Last" + index)
            .confirmed(false)
            .enabled(false)
            .authorities(List.of(Authority.CUSTOMER))
            .build())
        .when()
        .post("/users")
        .then()
        .statusCode(CREATED.getStatusCode())
        .extract().response();

    return response.getBody().as(User.class);
  }

  private void setUser(final AuthenticationResponse authenticationResponse, final User user) {
    final Response response = given()
        .contentType("application/json")
        .header("Authorization",
            "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
        .body(UserProfile.builder()
            .firstName(user.getFirstName() + "changed")
            .lastName(user.getLastName() + "changed")
            .build())
        .when()
        .put("/users/%d".formatted(user.getId()))
        .then()
        .statusCode(OK.getStatusCode())
        .extract().response();

    final User result = response.getBody().as(User.class);
    assertThat(result).isNotNull();
    assertThat(result.getFirstName()).endsWith("changed");
    assertThat(result.getLastName()).endsWith("changed");
  }

  private void setAuthorities(final AuthenticationResponse authenticationResponse, final Long id) {
    final Response response = given()
        .contentType("application/json")
        .header("Authorization",
            "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
        .body(List.of(Authority.CUSTOMER, Authority.EMPLOYEE))
        .when()
        .patch("/users/%d/authorities".formatted(id))
        .then()
        .statusCode(OK.getStatusCode())
        .extract().response();

    final User result = response.getBody().as(User.class);
    assertThat(result).isNotNull();
    assertThat(result.getAuthorities()).hasSize(2);
  }

  private void setConfirmed(final AuthenticationResponse authenticationResponse, final Long id) {
    final Response response = given()
        .contentType("application/json")
        .header("Authorization",
            "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
        .body(BooleanValue.builder().value(true).build())
        .when()
        .patch("/users/%d/confirm".formatted(id))
        .then()
        .statusCode(OK.getStatusCode())
        .extract().response();

    final User result = response.getBody().as(User.class);
    assertThat(result).isNotNull();
    assertThat(result.getConfirmed()).isTrue();
  }

  private void setEnabled(final AuthenticationResponse authenticationResponse, final Long id) {
    final Response response = given()
        .contentType("application/json")
        .header("Authorization",
            "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
        .body(BooleanValue.builder().value(true).build())
        .when()
        .patch("/users/%d/enable".formatted(id))
        .then()
        .statusCode(OK.getStatusCode())
        .extract().response();

    final User result = response.getBody().as(User.class);
    assertThat(result).isNotNull();
    assertThat(result.getEnabled()).isTrue();
  }

  private void deleteUser(final AuthenticationResponse authenticationResponse, final Long id) {
    given()
        .contentType("application/json")
        .header("Authorization",
            "%s %s".formatted(authenticationResponse.getType(), authenticationResponse.getToken()))
        .body(BooleanValue.builder().value(true).build())
        .when()
        .delete("/users/%d".formatted(id))
        .then()
        .statusCode(OK.getStatusCode());
  }

  private AuthenticationResponse signIn() {
    final Response response = given()
        .contentType("application/json")
        .body(SignIn.builder().email(commonConfigProperties.mail()).password("simple").build())
        .when()
        .post("/auth/sign-in")
        .then()
        .statusCode(OK.getStatusCode())
        .extract().response();

    return response.getBody().as(AuthenticationResponse.class);
  }
}