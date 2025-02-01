package sk.janobono.simple.dal.repository;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import sk.janobono.simple.common.exception.SimpleAuthServiceException;
import sk.janobono.simple.common.model.PageDto;
import sk.janobono.simple.common.model.PageableDto;
import sk.janobono.simple.common.model.UserSearchCriteriaDto;
import sk.janobono.simple.dal.domain.UserDo;

@ApplicationScoped
public class UserRepository implements PanacheRepository<UserDo> {

  public boolean existsById(final Long id) {
    return count("id", id) > 0;
  }

  public boolean existsByEmail(final String email) {
    return count("email", email) > 0;
  }

  public Optional<UserDo> findByEmail(final String email) {
    return Optional.ofNullable(find("email", email).firstResult());
  }

  public PageDto<UserDo> findAll(final UserSearchCriteriaDto criteria, final PageableDto pageable) {
    final long totalElements = getUsersTotalElements(criteria);
    final List<UserDo> content = getUsersContent(criteria, pageable);

    final int totalPages;
    if (totalElements == 0) {
      totalPages = 0;
    } else if (totalElements < pageable.size()) {
      totalPages = 1;
    } else {
      totalPages = (int) totalElements / pageable.size();
    }

    return new PageDto<>(
        totalElements,
        totalPages,
        pageable.page() == 0,
        pageable.page() == totalPages - 1,
        pageable.page(),
        pageable.size(),
        content,
        content.isEmpty()
    );
  }

  public UserDo getUserDo(final Long id) {
    return findByIdOptional(id)
        .orElseThrow(
            () -> SimpleAuthServiceException.USER_NOT_FOUND.exception("User with id {0} not found",
                id));
  }

  public UserDo getUserDo(final String email) {
    return findByEmail(email)
        .orElseThrow(() -> SimpleAuthServiceException.USER_NOT_FOUND.exception(
            "User with email {0} not found", email));
  }

  private long getUsersTotalElements(final UserSearchCriteriaDto criteria) {
    final EntityManager entityManager = getEntityManager();
    final CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
    final CriteriaQuery<Long> criteriaQuery = criteriaBuilder.createQuery(Long.class);
    final Root<UserDo> root = criteriaQuery.from(UserDo.class);

    criteriaQuery.select(criteriaBuilder.count(root));
    toPredicate(criteria, root, criteriaQuery, criteriaBuilder)
        .ifPresent(criteriaQuery::where);

    return entityManager.createQuery(criteriaQuery).getSingleResult();
  }

  private List<UserDo> getUsersContent(final UserSearchCriteriaDto criteria,
      final PageableDto pageable) {
    final EntityManager entityManager = getEntityManager();
    final CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
    final CriteriaQuery<UserDo> criteriaQuery = criteriaBuilder.createQuery(UserDo.class);
    final Root<UserDo> root = criteriaQuery.from(UserDo.class);

    criteriaQuery.select(root);
    toPredicate(criteria, root, criteriaQuery, criteriaBuilder)
        .ifPresent(criteriaQuery::where);

    if (pageable.ascending()) {
      criteriaQuery.orderBy(criteriaBuilder.asc(root.get(pageable.sortBy())));
    } else {
      criteriaQuery.orderBy(criteriaBuilder.desc(root.get(pageable.sortBy())));
    }

    final var query = entityManager.createQuery(criteriaQuery);
    query.setFirstResult(pageable.page() * pageable.size());
    query.setMaxResults(pageable.size());

    return query.getResultList();
  }

  public Optional<Predicate> toPredicate(
      final UserSearchCriteriaDto criteria,
      final Root<UserDo> root,
      final CriteriaQuery<?> criteriaQuery,
      final CriteriaBuilder criteriaBuilder
  ) {
    if (Optional.ofNullable(criteria.searchField()).filter(s -> !s.isBlank()).isEmpty()
        && Optional.ofNullable(criteria.email()).filter(s -> !s.isBlank()).isEmpty()
    ) {
      return Optional.empty();
    }

    final List<Predicate> predicates = new ArrayList<>();

    if (Optional.ofNullable(criteria.searchField()).filter(s -> !s.isBlank()).isPresent()) {
      predicates.add(searchFieldToPredicate(criteria.searchField(), root, criteriaBuilder));
    }

    if (Optional.ofNullable(criteria.email()).filter(s -> !s.isBlank()).isPresent()) {
      predicates.add(criteriaBuilder.equal(root.get("email"), criteria.email()));
    }

    return Optional.of(
        criteriaQuery.where(criteriaBuilder.and(predicates.toArray(Predicate[]::new)))
            .getRestriction());
  }

  private Predicate searchFieldToPredicate(
      final String searchField,
      final Root<?> root,
      final CriteriaBuilder criteriaBuilder
  ) {
    final List<Predicate> predicates = new ArrayList<>();
    final String[] fieldValues = searchField.split(" ");
    for (String fieldValue : fieldValues) {
      fieldValue = "%" + fieldValue + "%";
      final List<Predicate> subPredicates = new ArrayList<>();
      subPredicates.add(
          criteriaBuilder.like(toScDf(root.get("email"), criteriaBuilder), fieldValue));
      subPredicates.add(
          criteriaBuilder.like(toScDf(root.get("firstName"), criteriaBuilder), fieldValue));
      subPredicates.add(
          criteriaBuilder.like(toScDf(root.get("lastName"), criteriaBuilder), fieldValue));
      predicates.add(criteriaBuilder.or(subPredicates.toArray(Predicate[]::new)));
    }
    return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
  }

  private Expression<String> toScDf(final Path<String> path,
      final CriteriaBuilder criteriaBuilder) {
    return criteriaBuilder.lower(criteriaBuilder.function("unaccent", String.class, path));
  }
}
