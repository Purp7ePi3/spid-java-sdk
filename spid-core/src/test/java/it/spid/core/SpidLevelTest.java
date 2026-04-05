package it.spid.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import it.spid.core.model.SpidLevel;

public class SpidLevelTest {

  @Test
  void fromUri_level2() {
    SpidLevel level = SpidLevel.fromUri("https://www.spid.gov.it/SpidL2");
    assertEquals(SpidLevel.LEVEL_2, level);
  }

  @Test
  void fromUri_notValid_Exception() {
    assertThrows(IllegalArgumentException.class, () -> SpidLevel.fromUri("https://uri.non.valido"));
  }

  @Test
  void getValue_order() {
    assertTrue(SpidLevel.LEVEL_1.getValue() < SpidLevel.LEVEL_2.getValue());
    assertTrue(SpidLevel.LEVEL_2.getValue() < SpidLevel.LEVEL_3.getValue());
  }
}
