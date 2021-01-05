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

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticationControllerIT extends BaseIntegrationTest {

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
                mapFromJson(mvcResult.getResponse().getContentAsString(), AuthenticationResponseSO.class);
        assertThat(authenticationResponseSO.getType()).isEqualTo("Bearer");
        JwtToken.JwtUser tokenUser = jwtToken.parseToken(authenticationResponseSO.getToken());
        assertThat(tokenUser.getUsername()).isEqualTo("test");
        assertThat(tokenUser.getEnabled()).isTrue();
        assertThat(tokenUser.getAttributes().get("test")).isEqualTo("test");
        assertThat(tokenUser.getRoles().size()).isEqualTo(2);
    }

    @Test
    public void currentUser() throws Exception {
        JwtToken.JwtUser userPrincipal = new JwtToken.JwtUser();
        userPrincipal.setUsername("test");
        userPrincipal.setEnabled(true);
        userPrincipal.getRoles().add("test");
        userPrincipal.getAttributes().put("test", "test");
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        userPrincipal, null, userPrincipal.getAuthorities())
        );
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/current-user")).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        UserSO userSO = mapFromJson(mvcResult.getResponse().getContentAsString(), UserSO.class);
        assertThat(userSO).usingRecursiveComparison().ignoringFields("password", "roles").isEqualTo(userPrincipal);
    }

    private void createTestUser() {
        UserSO userSO = new UserSO();
        userSO.setUsername("test");
        userSO.setPassword("test");
        userSO.setEnabled(true);
        userSO.getRoles().add(new RoleSO(DefaultRole.ROLE_VIEW_USERS.getRoleName()));
        userSO.getRoles().add(new RoleSO(DefaultRole.ROLE_MANAGE_USERS.getRoleName()));
        userSO.getAttributes().put("test", "test");
        userApiService.addUser(userSO);
    }
}
