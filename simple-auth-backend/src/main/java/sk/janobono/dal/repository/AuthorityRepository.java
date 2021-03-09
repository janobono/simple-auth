package sk.janobono.dal.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sk.janobono.dal.domain.Authority;

import java.util.Optional;

public interface AuthorityRepository extends JpaRepository<Authority, Long> {

    Optional<Authority> findByName(String name);

    boolean existsByName(String name);
}
