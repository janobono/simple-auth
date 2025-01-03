package sk.janobono.simple.common.component;

import jakarta.enterprise.context.ApplicationScoped;
import sk.janobono.simple.common.model.PageableDto;

import java.util.Optional;

@ApplicationScoped
public class PageableUtil {

    public PageableDto toPageable(final Integer page, final Integer size, final String sort, final String sortField, final boolean ascending) {
        return new PageableDto(
                Optional.ofNullable(page).orElse(0),
                Optional.ofNullable(size).orElse(20),
                Optional.ofNullable(sort)
                        .filter(s -> !s.isBlank())
                        .orElseGet(() -> ascending ? sortField : "%s DESC".formatted(sortField))
        );
    }
}
