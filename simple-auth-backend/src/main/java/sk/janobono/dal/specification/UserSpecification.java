package sk.janobono.dal.specification;

import sk.janobono.dal.domain.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Predicate;
import javax.persistence.criteria.Root;
import java.util.ArrayList;
import java.util.List;

public class UserSpecification implements Specification<User> {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserSpecification.class);

    private final String searchField;

    public UserSpecification(String searchField) {
        this.searchField = searchField;
    }

    public Predicate toPredicate(Root<User> root, CriteriaQuery<?> criteriaQuery, CriteriaBuilder criteriaBuilder) {
        criteriaQuery.distinct(true);
        if (StringUtils.isEmpty(searchField)) {
            LOGGER.debug("Empty criteria.");
            return criteriaQuery.getRestriction();
        }

        List<Predicate> predicates = new ArrayList<>();
        if (!StringUtils.isEmpty(searchField)) {
            predicates.add(searchFieldToPredicate(searchField, root, criteriaBuilder));
        }

        return criteriaQuery.where(criteriaBuilder.and(predicates.toArray(Predicate[]::new))).getRestriction();
    }

    private Predicate searchFieldToPredicate(String searchField, Root<User> root, CriteriaBuilder criteriaBuilder) {
        List<Predicate> predicates = new ArrayList<>();
        String[] fieldValues = searchField.split(" ");
        for (String fieldValue : fieldValues) {
            predicates.add(criteriaBuilder.like(root.get("username"), "%" + fieldValue.toLowerCase() + "%"));
        }
        return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
    }
}
