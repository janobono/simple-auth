package sk.janobono.simple.common.component;

import static org.assertj.core.api.Assertions.assertThat;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

@QuarkusTest
class ScDfTest {

  private static final String TEXT = "ľščťžýáíéňäúô ĽŠČŤŽÝÁÍÉŇÄÚÔ";
  private static final String DF_RESULT = "lsctzyaienauo LSCTZYAIENAUO";
  private static final String SCDF_RESULT = "lsctzyaienauo lsctzyaienauo";

  @Inject
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
