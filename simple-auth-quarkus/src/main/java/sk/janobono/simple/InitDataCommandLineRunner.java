package sk.janobono.simple;

import io.quarkus.elytron.security.common.BcryptUtil;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.common.config.CommonConfigProperties;
import sk.janobono.simple.dal.domain.AuthorityDo;
import sk.janobono.simple.dal.domain.UserDo;
import sk.janobono.simple.dal.repository.AuthorityRepository;
import sk.janobono.simple.dal.repository.UserRepository;

@RequiredArgsConstructor(onConstructor = @__(@Inject))
@ApplicationScoped
public class InitDataCommandLineRunner {

  private static final String SIMPLE = "simple";

  private final CommonConfigProperties commonConfigProperties;
  private final AuthorityRepository authorityRepository;
  private final UserRepository userRepository;

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
          .password(BcryptUtil.bcryptHash(SIMPLE))
          .firstName(SIMPLE)
          .lastName(SIMPLE)
          .confirmed(true)
          .enabled(true)
          .authorities(authorityRepository.listAll())
          .build());
    }
  }
}