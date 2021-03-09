package sk.janobono.mapper;

import io.github.benas.randombeans.api.EnhancedRandom;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import sk.janobono.TestEnhancedRandomBuilder;
import sk.janobono.api.service.so.AuthoritySO;
import sk.janobono.dal.domain.Authority;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {AuthorityMapperImpl.class})
public class AuthorityMapperTest {

    @Autowired
    public AuthorityMapper mapper;

    public EnhancedRandom enhancedRandom = TestEnhancedRandomBuilder.build();

    @Test
    public void authorityToAuthoritySO() {
        Authority toMap = enhancedRandom.nextObject(Authority.class);
        AuthoritySO mapped = mapper.authorityToAuthoritySO(toMap);
        assertThat(toMap).usingRecursiveComparison().ignoringFields("id").isEqualTo(mapped);
    }
}
