package sk.janobono.simple.common.component;

import static org.assertj.core.api.Assertions.assertThat;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sk.janobono.simple.common.model.PageableDto;

@QuarkusTest
class PageableUtilTest {

    private PageableUtil pageableUtil;

    @BeforeEach
    void setUp() {
        pageableUtil = new PageableUtil();
    }

    @Test
    void toPageable_whenNullInput_thenExceptionThrown() {
        Assertions.assertThrows(
            IllegalArgumentException.class,
            () -> pageableUtil.toPageable(null, null, null, null, false)
        );
    }

    @Test
    void toPageable_whenSortField_thenResult() {
        // WHEN
        final PageableDto pageable = pageableUtil.toPageable(null, null, null, "id", false);

        // THEN
        assertThat(pageable).isNotNull();
        assertThat(pageable.page()).isEqualTo(0);
        assertThat(pageable.size()).isEqualTo(20);
        assertThat(pageable.sortBy()).isEqualTo("id");
        assertThat(pageable.ascending()).isFalse();
    }

    @Test
    void toPageable_whenValidInput_thenResult() {
        // WHEN
        final PageableDto pageable = pageableUtil.toPageable(10, 100, "id ASC", "id", false);

        // THEN
        assertThat(pageable).isNotNull();
        assertThat(pageable.page()).isEqualTo(10);
        assertThat(pageable.size()).isEqualTo(100);
        assertThat(pageable.sortBy()).isEqualTo("id");
        assertThat(pageable.ascending()).isTrue();
    }
}
