package sk.janobono.api.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import sk.janobono.BaseIntegrationTest;
import sk.janobono.api.service.so.*;

import static org.assertj.core.api.Assertions.assertThat;

public class RoleAndUserApiServiceIT extends BaseIntegrationTest {

    @Autowired
    private RoleApiService roleApiService;

    @Autowired
    private UserApiService userApiService;

    @Test
    public void fullTest() {
        Page<RoleDetailSO> roles = roleApiService.getRoles(Pageable.unpaged());
        assertThat(roles.getTotalElements()).isEqualTo(2L);

        RoleDetailSO roleDetailSO = roleApiService.addRole(new RoleSO("view-hotels"));
        RoleDetailSO roleDetailSO1 = roleApiService.addRole(new RoleSO("manage-hotels"));

        roles = roleApiService.getRoles(Pageable.unpaged());
        assertThat(roles.getTotalElements()).isEqualTo(4L);

        UserSO userSO = new UserSO();
        userSO.setUsername("trevor.ochmonek.dev");
        userSO.setPassword("MelmacAlf+456"); //$2a$10$DiZet0o1I9E1TogKsnTosuWr.jMuvFBnlknrLIcPhOebW0nXPyeXa
        userSO.setEnabled(true);
        userSO.getRoles().add(new RoleSO(DefaultRole.ROLE_VIEW_USERS.getRoleName()));
        userSO.getRoles().add(new RoleSO(DefaultRole.ROLE_MANAGE_USERS.getRoleName()));
        userSO.getRoles().add(new RoleSO("view-hotels"));
        userSO.getRoles().add(new RoleSO("manage-hotels"));
        userSO.getAttributes().put("email", "trevor.ochmonek@melmac.com");
        userSO.getAttributes().put("given_name", "Trevor");
        userSO.getAttributes().put("family_name", "Ochmonek");
        userSO.getAttributes().put("hotel_code", "emaem-123");
        UserDetailSO userDetailSO = userApiService.addUser(userSO);
        assertThat(userDetailSO).isNotNull();
        UserDetailSO userDetailSO1 = userApiService.getUser(userDetailSO.getId());
        assertThat(userDetailSO).usingRecursiveComparison().ignoringFields("roles").isEqualTo(userDetailSO1);

        roleApiService.deleteRole(roleDetailSO1.getId());
        userDetailSO1 = userApiService.getUser(userDetailSO.getId());
        assertThat(userDetailSO1.getRoles().size()).isEqualTo(3);
        userApiService.deleteUser(userDetailSO.getId());

        roles = roleApiService.getRoles(Pageable.unpaged());
        assertThat(roles.getTotalElements()).isEqualTo(3L);

        roleApiService.deleteRole(roleDetailSO.getId());
    }
}