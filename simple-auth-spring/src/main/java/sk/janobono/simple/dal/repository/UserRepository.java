package sk.janobono.simple.dal.repository;

import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import sk.janobono.simple.common.exception.SimpleAuthServiceException;
import sk.janobono.simple.dal.domain.UserDo;

public interface UserRepository extends JpaRepository<UserDo, Long> {

    boolean existsByEmail(String email);

    Optional<UserDo> findByEmail(String email);

    Page<UserDo> findAll(Specification<UserDo> spec, Pageable pageable);

    default UserDo getUserDo(final Long id) {
        return findById(id)
            .orElseThrow(() -> SimpleAuthServiceException.USER_NOT_FOUND.exception("User with id {0} not found", id));
    }

    default UserDo getUserDo(final String email) {
        return findByEmail(email)
            .orElseThrow(() -> SimpleAuthServiceException.USER_NOT_FOUND.exception("User with email {0} not found", email));
    }
}
