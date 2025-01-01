package sk.janobono.simple.common.component;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Optional;

@Component
public class PageableUtil {

    public Pageable toPageable(final Integer page, final Integer size, final List<String> sort, final String sortField, final boolean ascending) {
        return PageRequest.of(
                Optional.ofNullable(page).orElse(0),
                Optional.ofNullable(size).orElse(20),
                Optional.ofNullable(sort)
                        .filter(s -> !s.isEmpty())
                        .map(this::toOrder)
                        .orElseGet(() -> Sort.by(ascending ? Sort.Order.asc(sortField) : Sort.Order.desc(sortField)))
        );
    }

    private Sort toOrder(final List<String> sort) {
        final List<String> fieldNames = sort.stream().filter(field -> !field.equals("ASC") && !field.equals("DESC")).toList();
        if (fieldNames.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid sort parameter");
        }
        if (sort.stream().anyMatch(s -> s.equals("DESC"))) {
            return Sort.by(fieldNames.stream().map(Sort.Order::desc).toList());
        } else {
            return Sort.by(fieldNames.stream().map(Sort.Order::asc).toList());
        }
    }
}
