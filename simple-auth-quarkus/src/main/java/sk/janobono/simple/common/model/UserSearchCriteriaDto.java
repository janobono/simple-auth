package sk.janobono.simple.common.model;

import lombok.Builder;

@Builder
public record UserSearchCriteriaDto(
    String searchField,
    String email
) {

}
