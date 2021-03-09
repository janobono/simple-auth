package sk.janobono.api.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import sk.janobono.BaseIntegrationTest;
import sk.janobono.api.service.UserApiService;
import sk.janobono.api.service.so.*;
import sk.janobono.common.DefaultAuthority;
import sk.janobono.component.JwtToken;
import sk.janobono.dal.domain.Authority;
import sk.janobono.dal.domain.User;

import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

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
        assertThat(tokenUser.getAuthorities().size()).isEqualTo(2);
    }

    @Test
    public void currentUser() throws Exception {
        User user = new User();
        user.setId(1L);
        user.setUsername("test");
        user.setEnabled(true);
        user.getAuthorities().add(new Authority(1L, "test"));
        user.getAttributes().put("test", "test");
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        user, null, user.getAuthorities().stream()
                        .map(r -> new SimpleGrantedAuthority(r.getName())).collect(Collectors.toList())
                )
        );
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/current-user")).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        UserSO userSO = mapFromJson(mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8), UserSO.class);
        assertThat(userSO).usingRecursiveComparison().ignoringFields("password", "roles").isEqualTo(user);
    }

    private void createTestUser() {
        UserCreateSO userCreateSO = new UserCreateSO();
        userCreateSO.setUsername("test");
        userCreateSO.setPassword("test");
        userCreateSO.setEnabled(true);
        userCreateSO.getAuthorities().add(new AuthoritySO(1L, DefaultAuthority.VIEW_USERS.getAuthorityName()));
        userCreateSO.getAuthorities().add(new AuthoritySO(2L, DefaultAuthority.MANAGE_USERS.getAuthorityName()));
        userCreateSO.getAttributes().put("test", "test");
        userApiService.addUser(userCreateSO);
    }
}
