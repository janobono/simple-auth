package sk.janobono.simple.dal.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sk.janobono.simple.api.model.Authority;
import sk.janobono.simple.common.exception.SimpleAuthServiceException;
import sk.janobono.simple.dal.domain.AuthorityDo;

import java.util.Optional;

public interface AuthorityRepository extends JpaRepository<AuthorityDo, Long> {

    Optional<AuthorityDo> findByAuthority(Authority authority);

    default AuthorityDo getAuthorityDo(final Authority authority) {
        return findByAuthority(authority)
                .orElseThrow(() -> SimpleAuthServiceException.AUTHORITY_NOT_FOUND.exception("Authority {0} not found", authority));
    }
}
