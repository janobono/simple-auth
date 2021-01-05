package sk.janobono.mapper;

import io.github.benas.randombeans.api.EnhancedRandom;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import sk.janobono.TestEnhancedRandomBuilder;
import sk.janobono.api.service.so.UserDetailSO;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.dal.domain.User;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {RoleMapperImpl.class, UserMapperImpl.class})
public class UserMapperTest {

    @Autowired
    public UserMapper mapper;

    public EnhancedRandom enhancedRandom = TestEnhancedRandomBuilder.build();

    @Test
    public void userToUserDetailSO() {
        User user = enhancedRandom.nextObject(User.class);
        UserDetailSO userDetailSO = mapper.userToUserDetailSO(user);
        assertThat(user).usingRecursiveComparison().ignoringFields("roles").isEqualTo(userDetailSO);
    }

    @Test
    public void userToUserSO() {
        User user = enhancedRandom.nextObject(User.class);
        UserSO userSO = mapper.userToUserSO(user);
        assertThat(user).usingRecursiveComparison().ignoringFields("id", "roles").isEqualTo(userSO);
    }

    @Test
    public void userSOToUser() {
        UserSO userSO = enhancedRandom.nextObject(UserSO.class);
        User user = mapper.userSOToUser(userSO);
        assertThat(userSO).usingRecursiveComparison().ignoringFields("roles").isEqualTo(user);
    }
}
