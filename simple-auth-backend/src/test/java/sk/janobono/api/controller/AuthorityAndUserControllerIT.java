package sk.janobono.api.controller;

import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import sk.janobono.BaseIntegrationTest;
import sk.janobono.api.service.so.AuthoritySO;
import sk.janobono.api.service.so.UserCreateSO;
import sk.janobono.api.service.so.UserSO;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthorityAndUserControllerIT extends BaseIntegrationTest {

    @Test
    @WithMockUser(username = "test", authorities = {"manage-users"})
    public void fullTest() throws Exception {
        Page<AuthoritySO> authorities = getAuthorities(0, 10);
        assertThat(authorities.getTotalElements()).isEqualTo(2L);

        AuthoritySO authoritySO01 = addAuthority("view-hotels");
        AuthoritySO authoritySO02 = addAuthority("manage-hotels");
        AuthoritySO authoritySO03 = getAuthority(1L);
        AuthoritySO authoritySO04 = getAuthority(2L);

        authorities = getAuthorities(0, 5);
        assertThat(authorities.getTotalElements()).isEqualTo(4L);

        UserCreateSO userCreateSO = new UserCreateSO();
        userCreateSO.setUsername("trevor.ochmonek.dev");
        userCreateSO.setPassword("MelmacAlf+456"); //$2a$10$DiZet0o1I9E1TogKsnTosuWr.jMuvFBnlknrLIcPhOebW0nXPyeXa
        userCreateSO.setEnabled(true);
        userCreateSO.getAuthorities().add(authoritySO01);
        userCreateSO.getAuthorities().add(authoritySO02);
        userCreateSO.getAuthorities().add(authoritySO03);
        userCreateSO.getAuthorities().add(authoritySO04);
        userCreateSO.getAttributes().put("email", "trevor.ochmonek@melmac.com");
        userCreateSO.getAttributes().put("given_name", "Trevor");
        userCreateSO.getAttributes().put("family_name", "Ochmonek");
        userCreateSO.getAttributes().put("hotel_code", "emaem-123");
        UserSO userSO = addUser(userCreateSO);
        assertThat(userSO).isNotNull();
        UserSO userSO1 = getUser(userSO.getId());
        assertThat(userSO).usingRecursiveComparison().ignoringFields("roles").isEqualTo(userSO1);

        Page<UserSO> users = getUsers("revo", 0, 5);
        assertThat(users.getTotalElements()).isEqualTo(1L);
        assertThat(userSO1).usingRecursiveComparison().isEqualTo(users.getContent().get(0));

        deleteAuthority(authoritySO01.getId());
        userSO1 = getUser(userSO.getId());
        assertThat(userSO1.getAuthorities().size()).isEqualTo(3);
        deleteUser(userSO.getId());

        authorities = getAuthorities(0, 7);
        assertThat(authorities.getTotalElements()).isEqualTo(3L);

        deleteAuthority(authoritySO02.getId());
    }

    private Page<AuthoritySO> getAuthorities(
            int page,
            int size
    ) throws Exception {
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get("/authorities");
        builder.param("page", Integer.toString(page));
        builder.param("size", Integer.toString(size));
        MvcResult mvcResult = mvc.perform(builder).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        return mapPagedResponse(mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8), AuthoritySO.class);
    }

    private AuthoritySO addAuthority(String authority) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.post("/authorities")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapToJson(authority))).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        return mapFromJson(mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8), AuthoritySO.class);
    }

    private AuthoritySO getAuthority(Long id) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/authorities/" + id)).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        return mapFromJson(mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8), AuthoritySO.class);
    }

    private void deleteAuthority(Long id) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.delete("/authorities/" + id)).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    private UserSO addUser(UserCreateSO userCreateSO) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.post("/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapToJson(userCreateSO))).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        return mapFromJson(mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8), UserSO.class);
    }

    private UserSO getUser(Long id) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/users/" + id)).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        return mapFromJson(mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8), UserSO.class);
    }

    private Page<UserSO> getUsers(
            String searchField,
            int page,
            int size
    ) throws Exception {
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get("/users");
        builder.param("search-field", searchField);
        builder.param("page", Integer.toString(page));
        builder.param("size", Integer.toString(size));
        MvcResult mvcResult = mvc.perform(builder).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        return mapPagedResponse(mvcResult.getResponse().getContentAsString(StandardCharsets.UTF_8), UserSO.class);
    }

    private void deleteUser(Long id) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.delete("/users/" + id)).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
    }
}
