package sk.janobono.simple.business.model;

import lombok.Builder;

@Builder
public record UserSearchCriteriaData(
        String searchField,
        String email
) {
}
