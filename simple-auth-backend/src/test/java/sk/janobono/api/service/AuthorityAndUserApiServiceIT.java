package sk.janobono.api.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import sk.janobono.BaseIntegrationTest;
import sk.janobono.api.service.so.AuthoritySO;
import sk.janobono.api.service.so.UserCreateSO;
import sk.janobono.api.service.so.UserSO;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthorityAndUserApiServiceIT extends BaseIntegrationTest {

    @Autowired
    private AuthorityApiService roleApiService;

    @Autowired
    private UserApiService userApiService;

    @Test
    public void fullTest() {
        Page<AuthoritySO> authorities = roleApiService.getAuthorities(Pageable.unpaged());
        assertThat(authorities.getTotalElements()).isEqualTo(2L);

        AuthoritySO authoritySO01 = roleApiService.addAuthority("view-hotels");
        AuthoritySO authoritySO02 = roleApiService.addAuthority("manage-hotels");
        AuthoritySO authoritySO03 = roleApiService.getAuthority(1L);
        AuthoritySO authoritySO04 = roleApiService.getAuthority(2L);

        authorities = roleApiService.getAuthorities(Pageable.unpaged());
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
        UserSO userSO = userApiService.addUser(userCreateSO);
        assertThat(userSO).isNotNull();
        UserSO userSO1 = userApiService.getUser(userSO.getId());
        assertThat(userSO).usingRecursiveComparison().ignoringFields("authorities").isEqualTo(userSO1);

        Page<UserSO> users = userApiService.getUsers("revo", Pageable.unpaged());
        assertThat(users.getTotalElements()).isEqualTo(1L);
        assertThat(userSO1).usingRecursiveComparison().isEqualTo(users.getContent().get(0));

        roleApiService.deleteAuthority(authoritySO01.getId());
        userSO1 = userApiService.getUser(userSO.getId());
        assertThat(userSO1.getAuthorities().size()).isEqualTo(3);
        userApiService.deleteUser(userSO.getId());

        authorities = roleApiService.getAuthorities(Pageable.unpaged());
        assertThat(authorities.getTotalElements()).isEqualTo(3L);

        roleApiService.deleteAuthority(authoritySO02.getId());
    }
}
