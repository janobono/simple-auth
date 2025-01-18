package sk.janobono.simple.common.component;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(
    classes = {ScDf.class}
)
class ScDfTest {

    private static final String TEXT = "ľščťžýáíéňäúô ĽŠČŤŽÝÁÍÉŇÄÚÔ";
    private static final String DF_RESULT = "lsctzyaienauo LSCTZYAIENAUO";
    private static final String SCDF_RESULT = "lsctzyaienauo lsctzyaienauo";

    @Autowired
    public ScDf scdf;

    @Test
    void toDf_TestText_EqualsToExpectedResult() {
        assertThat(scdf.toDf(TEXT)).isEqualTo(DF_RESULT);
    }

    @Test
    void toScDf_TestText_EqualsToExpectedResult() {
        assertThat(scdf.toScDf(TEXT)).isEqualTo(SCDF_RESULT);
    }
}
