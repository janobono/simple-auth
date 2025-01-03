package sk.janobono.simple.common.component;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(
        classes = {PageableUtil.class}
)
class PageableUtilTest {

    @Autowired
    public PageableUtil pageableUtil;

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
        final Pageable pageable = pageableUtil.toPageable(null, null, null, "id", false);

        // THEN
        assertThat(pageable).isNotNull();
        assertThat(pageable.getPageNumber()).isEqualTo(0);
        assertThat(pageable.getPageSize()).isEqualTo(20);
        assertThat(pageable.getSort().isSorted()).isTrue();
    }

    @Test
    void toPageable_whenValidInput_thenResult() {
        // WHEN
        final Pageable pageable = pageableUtil.toPageable(10, 100, "id ASC", "id", false);

        // THEN
        assertThat(pageable).isNotNull();
        assertThat(pageable.getPageNumber()).isEqualTo(10);
        assertThat(pageable.getPageSize()).isEqualTo(100);
        assertThat(pageable.getSort().isSorted()).isTrue();
    }
}
