package sk.janobono.api.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import sk.janobono.BaseIntegrationTest;
import sk.janobono.api.service.UserApiService;
import sk.janobono.api.service.so.*;
import sk.janobono.component.JwtToken;
import sk.janobono.dal.domain.Role;
import sk.janobono.dal.domain.User;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthControllerIT extends BaseIntegrationTest {

    @Autowired
    private UserApiService userApiService;

    @Autowired
    private JwtToken jwtToken;

    @Test
    public void authenticate() throws Exception {
        createTestUser();
        AuthenticationRequestSO authenticationRequestSO = new AuthenticationRequestSO();
        authenticationRequestSO.setUsername("test");
        authenticationRequestSO.setPassword("test");

        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.post("/authenticate")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapToJson(authenticationRequestSO))).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());

        AuthenticationResponseSO authenticationResponseSO =
                mapFromJson(mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8), AuthenticationResponseSO.class);
        assertThat(authenticationResponseSO.getType()).isEqualTo("Bearer");
        User tokenUser = jwtToken.parseToken(authenticationResponseSO.getToken());
        assertThat(tokenUser.getUsername()).isEqualTo("test");
        assertThat(tokenUser.getEnabled()).isTrue();
        assertThat(tokenUser.getAttributes().get("test")).isEqualTo("test");
        assertThat(tokenUser.getRoles().size()).isEqualTo(2);
    }

    @Test
    public void currentUser() throws Exception {
        User userPrincipal = new User();
        userPrincipal.setId(1L);
        userPrincipal.setUsername("test");
        userPrincipal.setEnabled(true);
        userPrincipal.getRoles().add(new Role(1L, "test"));
        userPrincipal.getAttributes().put("test", "test");
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        userPrincipal, null, userPrincipal.getAuthorities())
        );
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/current-user")).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        UserDetailSO userDetailSO = mapFromJson(mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8), UserDetailSO.class);
        assertThat(userDetailSO).usingRecursiveComparison().ignoringFields("password", "roles").isEqualTo(userPrincipal);
    }

    private void createTestUser() {
        UserSO userSO = new UserSO();
        userSO.setUsername("test");
        userSO.setPassword("test");
        userSO.setEnabled(true);
        userSO.getRoles().add(new RoleDetailSO(1L, DefaultRole.ROLE_VIEW_USERS.getRoleName()));
        userSO.getRoles().add(new RoleDetailSO(2L, DefaultRole.ROLE_MANAGE_USERS.getRoleName()));
        userSO.getAttributes().put("test", "test");
        userApiService.addUser(userSO);
    }
}
