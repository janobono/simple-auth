package sk.janobono.simple.common.component;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ScDfTest {

    private static final String TEXT = "ľščťžýáíéňäúô ĽŠČŤŽÝÁÍÉŇÄÚÔ";
    private static final String DF_RESULT = "lsctzyaienauo LSCTZYAIENAUO";
    private static final String SCDF_RESULT = "lsctzyaienauo lsctzyaienauo";

    private ScDf scdf;

    @BeforeEach
    void setUp() {
        scdf = new ScDf();
    }

    @Test
    void toDf_TestText_EqualsToExpectedResult() {
        assertThat(scdf.toDf(TEXT)).isEqualTo(DF_RESULT);
    }

    @Test
    void toScDf_TestText_EqualsToExpectedResult() {
        assertThat(scdf.toScDf(TEXT)).isEqualTo(SCDF_RESULT);
    }
}
