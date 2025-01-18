package sk.janobono.simple.common.model;

public record PageableDto(
    Integer page,
    Integer size,
    String sortBy,
    boolean ascending
) {

}
