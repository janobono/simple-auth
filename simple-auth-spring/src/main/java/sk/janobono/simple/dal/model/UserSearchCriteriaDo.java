package sk.janobono.simple.dal.model;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import org.springframework.data.jpa.domain.Specification;
import sk.janobono.simple.dal.domain.UserDo;

@Builder
public record UserSearchCriteriaDo(
    String searchField,
    String email
) implements Specification<UserDo> {

    @Override
    public Predicate toPredicate(final Root<UserDo> root, final CriteriaQuery<?> criteriaQuery, final CriteriaBuilder criteriaBuilder) {
        if (Optional.ofNullable(searchField).filter(s -> !s.isBlank()).isEmpty()
            && Optional.ofNullable(email).filter(s -> !s.isBlank()).isEmpty()
        ) {
            return criteriaQuery.getRestriction();
        }

        final List<Predicate> predicates = new ArrayList<>();

        if (Optional.ofNullable(searchField).filter(s -> !s.isBlank()).isPresent()) {
            predicates.add(searchFieldToPredicate(root, criteriaBuilder));
        }

        if (Optional.ofNullable(email).filter(s -> !s.isBlank()).isPresent()) {
            predicates.add(criteriaBuilder.equal(root.get("email"), email));
        }

        return criteriaQuery.where(criteriaBuilder.and(predicates.toArray(Predicate[]::new))).getRestriction();
    }

    private Predicate searchFieldToPredicate(final Root<UserDo> root, final CriteriaBuilder criteriaBuilder) {
        final List<Predicate> predicates = new ArrayList<>();
        final String[] fieldValues = searchField.split(" ");
        for (String fieldValue : fieldValues) {
            fieldValue = "%" + fieldValue + "%";
            final List<Predicate> subPredicates = new ArrayList<>();
            subPredicates.add(criteriaBuilder.like(toScDf(root.get("email"), criteriaBuilder), fieldValue));
            subPredicates.add(criteriaBuilder.like(toScDf(root.get("firstName"), criteriaBuilder), fieldValue));
            subPredicates.add(criteriaBuilder.like(toScDf(root.get("lastName"), criteriaBuilder), fieldValue));
            predicates.add(criteriaBuilder.or(subPredicates.toArray(Predicate[]::new)));
        }
        return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
    }

    private Expression<String> toScDf(final Path<String> path, final CriteriaBuilder criteriaBuilder) {
        return criteriaBuilder.lower(criteriaBuilder.function("unaccent", String.class, path));
    }
}
