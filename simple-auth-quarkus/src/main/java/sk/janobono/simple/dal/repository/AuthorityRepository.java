package sk.janobono.simple.dal.repository;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.common.exception.SimpleAuthServiceException;
import sk.janobono.simple.dal.domain.AuthorityDo;

import java.util.Optional;

@ApplicationScoped
public class AuthorityRepository implements PanacheRepository<AuthorityDo> {

    public Optional<AuthorityDo> findByAuthority(final Authority authority) {
        return Optional.ofNullable(find("authority", authority).firstResult());
    }

    public AuthorityDo getAuthorityDo(final Authority authority) {
        return findByAuthority(authority)
                .orElseThrow(() -> SimpleAuthServiceException.AUTHORITY_NOT_FOUND.exception("Authority {0} not found", authority));
    }
}
