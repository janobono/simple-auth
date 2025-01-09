package sk.janobono.simple.common.component;

import jakarta.enterprise.context.ApplicationScoped;
import java.util.Optional;
import sk.janobono.simple.common.model.PageableDto;

@ApplicationScoped
public class PageableUtil {

    public PageableDto toPageable(final Integer page, final Integer size, final String sort, final String sortField, final boolean ascending) {
        return new PageableDto(
            Optional.ofNullable(page).orElse(0),
            Optional.ofNullable(size).orElse(20),
            Optional.ofNullable(sort)
                .filter(s -> !s.isBlank())
                .map(s -> s.split(" ")[0])
                .orElse(sortField),
            Optional.ofNullable(sort)
                .filter(s -> !s.isBlank())
                .map(s -> s.split(" "))
                .map(s -> s.length <= 1 || "asc".equalsIgnoreCase(s[1]))
                .orElseGet(() -> ascending)
        );
    }
}
