package sk.janobono.component;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import sk.janobono.BaseIntegrationTest;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtTokenIT extends BaseIntegrationTest {

    @Autowired
    private JwtToken jwtToken;

    @Test
    public void tokenTest() throws Exception {
        JwtToken.JwtUser jwtUser1 = new JwtToken.JwtUser();
        jwtUser1.setId(1000L);
        jwtUser1.setUsername("test");
        jwtUser1.setEnabled(true);
        jwtUser1.getRoles().add("test");
        jwtUser1.getAttributes().put("test", "test");
        String token = jwtToken.generateToken(jwtUser1, System.currentTimeMillis());
        System.out.println(token);
        JwtToken.JwtUser jwtUser2 = jwtToken.parseToken(token);
        assertThat(jwtUser1).usingRecursiveComparison().isEqualTo(jwtUser2);
    }
}
