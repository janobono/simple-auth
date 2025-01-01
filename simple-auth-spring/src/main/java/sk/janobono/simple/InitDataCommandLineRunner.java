package sk.janobono.simple;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.dal.domain.AuthorityDo;
import sk.janobono.simple.dal.domain.UserDo;
import sk.janobono.simple.dal.repository.AuthorityRepository;
import sk.janobono.simple.dal.repository.UserRepository;

@RequiredArgsConstructor
@Component
public class InitDataCommandLineRunner implements CommandLineRunner {

    private final CommonConfigProperties commonConfigProperties;
    private final PasswordEncoder passwordEncoder;
    private final AuthorityRepository authorityRepository;
    private final UserRepository userRepository;

    @Override
    public void run(final String... args) {
        initAuthorities();
        initUsers();
    }

    private void initAuthorities() {
        if (authorityRepository.count() == 0L) {
            for (final Authority authority : Authority.values()) {
                authorityRepository.save(AuthorityDo.builder().authority(authority).build());
            }
        }
    }

    private void initUsers() {
        if (userRepository.count() == 0L) {
            userRepository.save(UserDo.builder()
                    .email(commonConfigProperties.mail())
                    .password(passwordEncoder.encode("simple"))
                    .firstName("simple")
                    .lastName("simple")
                    .confirmed(true)
                    .enabled(true)
                    .authorities(authorityRepository.findAll())
                    .build());
        }
    }
}
