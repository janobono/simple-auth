package sk.janobono.simple.dal.repository;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import sk.janobono.simple.common.exception.SimpleAuthServiceException;
import sk.janobono.simple.common.model.PageDto;
import sk.janobono.simple.common.model.PageableDto;
import sk.janobono.simple.common.model.UserSearchCriteriaDto;
import sk.janobono.simple.dal.domain.UserDo;

import java.util.Optional;

@ApplicationScoped
public class UserRepository implements PanacheRepository<UserDo> {

    public boolean existsById(Long id) {
        // TODO
        return false;
    }

    public boolean existsByEmail(final String email) {
        // TODO
        return false;
    }

    public Optional<UserDo> findByEmail(String email) {
        // TODO
        return Optional.empty();
    }

    public PageDto<UserDo> findAll(final UserSearchCriteriaDto criteria, final PageableDto pageable) {

        return null;
    }

    public UserDo getUserDo(final Long id) {
        return findByIdOptional(id)
                .orElseThrow(() -> SimpleAuthServiceException.USER_NOT_FOUND.exception("User with id {0} not found", id));
    }

    public UserDo getUserDo(final String email) {
        return findByEmail(email)
                .orElseThrow(() -> SimpleAuthServiceException.USER_NOT_FOUND.exception("User with email {0} not found", email));
    }


}
