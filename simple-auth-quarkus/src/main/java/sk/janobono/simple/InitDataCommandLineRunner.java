package sk.janobono.simple;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.dal.domain.AuthorityDo;
import sk.janobono.simple.dal.domain.UserDo;
import sk.janobono.simple.dal.repository.AuthorityRepository;
import sk.janobono.simple.dal.repository.UserRepository;

@ApplicationScoped
public class InitDataCommandLineRunner {

    @Inject
    CommonConfigProperties commonConfigProperties;

    @Inject
    AuthorityRepository authorityRepository;

    @Inject
    UserRepository userRepository;

    @Transactional
    public void onStart(@Observes final StartupEvent ev) {
        initAuthorities();
        initUsers();
    }

    public void initAuthorities() {
        if (authorityRepository.count() == 0L) {
            for (final Authority authority : Authority.values()) {
                authorityRepository.persist(AuthorityDo.builder().authority(authority).build());
            }
        }
    }

    public void initUsers() {
        if (userRepository.count() == 0L) {
            userRepository.persist(UserDo.builder()
                .email(commonConfigProperties.mail())
                .password("simple") // Replace with actual password encoding
                .firstName("simple")
                .lastName("simple")
                .confirmed(true)
                .enabled(true)
                .authorities(authorityRepository.listAll())
                .build());
        }
    }
}