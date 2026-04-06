package it.spid.validator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RequestIdStoreTest {
  private RequestIdStore store;

  @BeforeEach
  void setup() {
    store = new RequestIdStore();
  }

  @Test
  void register_e_consume() {
    store.register("_req1");
    assertDoesNotThrow(() -> store.consumeOrThrow("_req1"));
  }

  @Test
  void consume_double_trow_replayAttack() {
    store.register("_req1");
    store.consumeOrThrow("_req1");

    assertThrows(SecurityException.class, () -> store.consumeOrThrow("_req1"));
  }

  @Test
  void consume_noReg() {
    assertThrows(SecurityException.class, () -> store.consumeOrThrow("_req1"));
  }

  @Test
  void double_reg() {
    store.register("_req1");
    assertThrows(SecurityException.class, () -> store.register("_req1"));
  }

  @Test
  void on_expired() throws InterruptedException {
    // TTL 1 sec per test
    RequestIdStore shortStore = new RequestIdStore(1);
    shortStore.register("_req1");
    Thread.sleep(1100);
    assertThrows(SecurityException.class, () -> shortStore.consumeOrThrow("_req1"));
  }

  @Test
  void isValid_afterConsume() {
    store.register("_req1");
    assertTrue(store.isValid("_req1"));
    store.consumeOrThrow("_req1");
    assertFalse(store.isValid("_req1"));
  }

  @Test
  void nullId() {
    assertThrows(IllegalArgumentException.class, () -> store.register(null));
    assertThrows(IllegalArgumentException.class, () -> store.register("  "));
  }

  @Test
  void size() {
    assertEquals(0, store.size());
    store.register("_req1");
    store.register("_req2");
    assertEquals(2, store.size());
    store.consumeOrThrow("_req1");
    assertEquals(1, store.size());
  }
}
