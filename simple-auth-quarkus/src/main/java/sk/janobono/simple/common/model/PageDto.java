package sk.janobono.simple.common.model;

import java.util.List;

public record PageDto<T>(
        Long totalElements,
        Integer totalPages,
        Boolean first,
        Boolean last,
        Integer page,
        Integer size,
        List<T> content,
        Boolean empty
) {
}
