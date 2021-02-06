package sk.janobono.api.controller;

import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import sk.janobono.BaseIntegrationTest;
import sk.janobono.api.service.so.RoleDetailSO;
import sk.janobono.api.service.so.RoleSO;
import sk.janobono.api.service.so.UserDetailSO;
import sk.janobono.api.service.so.UserSO;

import static org.assertj.core.api.Assertions.assertThat;

public class RoleAndUserControllerIT extends BaseIntegrationTest {

    @Test
    @WithMockUser(username = "test", authorities = {"manage-users"})
    public void fullTest() throws Exception {
        Page<RoleDetailSO> roles = getRoles(0, 10);
        assertThat(roles.getTotalElements()).isEqualTo(2L);

        RoleDetailSO roleDetailSO = addRole(new RoleSO("view-hotels"));
        RoleDetailSO roleDetailSO1 = addRole(new RoleSO("manage-hotels"));
        RoleDetailSO roleDetailSO2 = getRole(1L);
        RoleDetailSO roleDetailSO3 = getRole(2L);

        roles = getRoles(0, 5);
        assertThat(roles.getTotalElements()).isEqualTo(4L);

        UserSO userSO = new UserSO();
        userSO.setUsername("trevor.ochmonek.dev");
        userSO.setPassword("MelmacAlf+456"); //$2a$10$DiZet0o1I9E1TogKsnTosuWr.jMuvFBnlknrLIcPhOebW0nXPyeXa
        userSO.setEnabled(true);
        userSO.getRoles().add(roleDetailSO);
        userSO.getRoles().add(roleDetailSO1);
        userSO.getRoles().add(roleDetailSO2);
        userSO.getRoles().add(roleDetailSO3);
        userSO.getAttributes().put("email", "trevor.ochmonek@melmac.com");
        userSO.getAttributes().put("given_name", "Trevor");
        userSO.getAttributes().put("family_name", "Ochmonek");
        userSO.getAttributes().put("hotel_code", "emaem-123");
        UserDetailSO userDetailSO = addUser(userSO);
        assertThat(userDetailSO).isNotNull();
        UserDetailSO userDetailSO1 = getUser(userDetailSO.getId());
        assertThat(userDetailSO).usingRecursiveComparison().ignoringFields("roles").isEqualTo(userDetailSO1);

        Page<UserDetailSO> users = getUsers("revo", 0, 5);
        assertThat(users.getTotalElements()).isEqualTo(1L);
        assertThat(userDetailSO1).usingRecursiveComparison().isEqualTo(users.getContent().get(0));

        deleteRole(roleDetailSO1.getId());
        userDetailSO1 = getUser(userDetailSO.getId());
        assertThat(userDetailSO1.getRoles().size()).isEqualTo(3);
        deleteUser(userDetailSO.getId());

        roles = getRoles(0, 7);
        assertThat(roles.getTotalElements()).isEqualTo(3L);

        deleteRole(roleDetailSO.getId());
    }

    private Page<RoleDetailSO> getRoles(
            int page,
            int size
    ) throws Exception {
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get("/roles");
        builder.param("page", Integer.toString(page));
        builder.param("size", Integer.toString(size));
        MvcResult mvcResult = mvc.perform(builder).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        return mapPagedResponse(mvcResult.getResponse().getContentAsString(), RoleDetailSO.class);
    }

    private RoleDetailSO addRole(RoleSO roleSO) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.post("/roles")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapToJson(roleSO))).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        return mapFromJson(mvcResult.getResponse().getContentAsString(), RoleDetailSO.class);
    }

    private RoleDetailSO getRole(Long id) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/roles/" + id)).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        return mapFromJson(mvcResult.getResponse().getContentAsString(), RoleDetailSO.class);
    }

    private void deleteRole(Long id) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.delete("/roles/" + id)).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    private UserDetailSO addUser(UserSO userSO) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.post("/users")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapToJson(userSO))).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.CREATED.value());
        return mapFromJson(mvcResult.getResponse().getContentAsString(), UserDetailSO.class);
    }

    private UserDetailSO getUser(Long id) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.get("/users/" + id)).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
        return mapFromJson(mvcResult.getResponse().getContentAsString(), UserDetailSO.class);
    }

    private Page<UserDetailSO> getUsers(
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
        return mapPagedResponse(mvcResult.getResponse().getContentAsString(), UserDetailSO.class);
    }

    private void deleteUser(Long id) throws Exception {
        MvcResult mvcResult = mvc.perform(MockMvcRequestBuilders.delete("/users/" + id)).andReturn();
        assertThat(mvcResult.getResponse().getStatus()).isEqualTo(HttpStatus.OK.value());
    }
}
