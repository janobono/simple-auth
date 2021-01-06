package sk.janobono.mapper;

import io.github.benas.randombeans.api.EnhancedRandom;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import sk.janobono.TestEnhancedRandomBuilder;
import sk.janobono.api.service.so.RoleDetailSO;
import sk.janobono.api.service.so.RoleSO;
import sk.janobono.dal.domain.Role;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {RoleMapperImpl.class})
public class RoleMapperTest {

    @Autowired
    public RoleMapper mapper;

    public EnhancedRandom enhancedRandom = TestEnhancedRandomBuilder.build();

    @Test
    public void roleDetailSOToRole() {
        RoleDetailSO roleDetailSO = enhancedRandom.nextObject(RoleDetailSO.class);
        Role role = mapper.roleDetailSOToRole(roleDetailSO);
        assertThat(roleDetailSO).usingRecursiveComparison().isEqualTo(role);
    }

    @Test
    public void roleToRoleDetailSO() {
        Role role = enhancedRandom.nextObject(Role.class);
        RoleDetailSO roleDetailSO = mapper.roleToRoleDetailSO(role);
        assertThat(role).usingRecursiveComparison().isEqualTo(roleDetailSO);
    }

    @Test
    public void roleToRoleSO() {
        Role role = enhancedRandom.nextObject(Role.class);
        RoleSO roleSO = mapper.roleToRoleSO(role);
        assertThat(role).usingRecursiveComparison().ignoringFields("id").isEqualTo(roleSO);
    }

    @Test
    public void userSOToUser() {
        RoleSO roleSO = enhancedRandom.nextObject(RoleSO.class);
        Role role = mapper.roleSOToRole(roleSO);
        assertThat(roleSO).usingRecursiveComparison().isEqualTo(role);
    }
}
