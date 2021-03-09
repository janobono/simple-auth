package sk.janobono.component;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import sk.janobono.BaseIntegrationTest;
import sk.janobono.dal.domain.Authority;
import sk.janobono.dal.domain.User;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtTokenIT extends BaseIntegrationTest {

    @Autowired
    private JwtToken jwtToken;

    @Test
    public void tokenTest() {
        User user1 = new User();
        user1.setId(1000L);
        user1.setUsername("test");
        user1.setEnabled(true);
        user1.getAuthorities().add(new Authority(1L, "test"));
        user1.getAttributes().put("test", "test");
        String token = jwtToken.generateToken(user1, System.currentTimeMillis());
        System.out.println(token);
        User user2 = jwtToken.parseToken(token);
        assertThat(user1).usingRecursiveComparison().isEqualTo(user2);
    }
}
