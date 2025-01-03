package sk.janobono.simple.dal.repository;

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import jakarta.enterprise.context.ApplicationScoped;
import sk.janobono.simple.common.exception.SimpleAuthServiceException;
import sk.janobono.simple.common.model.PageDto;
import sk.janobono.simple.common.model.PageableDto;
import sk.janobono.simple.common.model.UserSearchCriteriaDto;
import sk.janobono.simple.dal.domain.UserDo;

import java.util.*;

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
        final StringBuilder query = new StringBuilder("1=1");  // Always true to allow dynamic appending
        final Map<String, Object> params = new HashMap<>();

        Optional.ofNullable(criteria.searchField()).filter(s -> !s.isBlank()).ifPresent(value -> {
            final String[] fieldValues = value.split(" ");
            final List<String> subQueries = new ArrayList<>();
            for (String fieldValue : fieldValues) {
                fieldValue = "%" + fieldValue + "%";
                final StringBuilder subQuery = new StringBuilder("1=1");

                subQuery.append(" AND LOWER(UNACCENT(email)) like :subEmail%d".formatted(subQueries.size()));
                params.put("subEmail%d".formatted(subQueries.size()), fieldValue);

                subQuery.append(" AND LOWER(UNACCENT(firstName)) like :firstName%d".formatted(subQueries.size()));
                params.put("firstName%d".formatted(subQueries.size()), fieldValue);

                subQuery.append(" AND LOWER(UNACCENT(lastName)) like :lastName%d".formatted(subQueries.size()));
                params.put("lastName%d".formatted(subQueries.size()), fieldValue);

                subQueries.add(subQuery.toString());
            }

            if (!subQueries.isEmpty()) {
                query.append(" AND (");
                for (int i = 0; i < subQueries.size(); i++) {
                    query.append("(%s)".formatted(subQueries.get(i)));
                    if (i != subQueries.size() - 1) {
                        query.append(" OR ");
                    }
                }
                query.append(")");
            }
        });

        Optional.ofNullable(criteria.email()).filter(s -> !s.isBlank()).ifPresent(value -> {
            query.append(" AND email = :email");
            params.put("email", value);
        });

        final long totalElements = count(query.toString(), params);
        final List<UserDo> content = find(query.toString() + " ORDER BY " + pageable.sort(), params)
                .page(pageable.page(), pageable.size())
                .list();

        final int totalPages = (int) totalElements / pageable.size();

        return new PageDto<>(
                totalElements,
                totalPages,
                pageable.page() == 0,
                pageable.page() == totalPages - 1,
                pageable.page(),
                content.size(),
                content,
                content.isEmpty()
        );
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
