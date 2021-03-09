package sk.janobono.mapper;

import io.github.benas.randombeans.api.EnhancedRandom;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import sk.janobono.TestEnhancedRandomBuilder;
import sk.janobono.api.service.so.UserSO;
import sk.janobono.dal.domain.Authority;
import sk.janobono.dal.domain.User;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {AuthorityMapperImpl.class, UserMapperImpl.class})
public class UserMapperTest {

    @Autowired
    public UserMapper mapper;

    public EnhancedRandom enhancedRandom = TestEnhancedRandomBuilder.build();

    @Test
    public void userToUserSO() {
        User toMap = enhancedRandom.nextObject(User.class);
        UserSO mapped = mapper.userToUserSO(toMap);
        assertThat(toMap).usingRecursiveComparison().ignoringFields("roles").isEqualTo(mapped);
        for (Authority authority : toMap.getAuthorities()) {
            assertThat(authority).usingRecursiveComparison().isEqualTo(
                    mapped.getAuthorities().stream().filter(a -> a.getId().equals(authority.getId())).findFirst().get()
            );
        }
    }
}
