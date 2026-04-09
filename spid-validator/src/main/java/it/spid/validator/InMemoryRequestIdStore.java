package it.spid.validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryRequestIdStore implements RequestIdStore {

  private static final Logger log = LoggerFactory.getLogger(InMemoryRequestIdStore.class);
  private static final long DEFAULT_TTL_SECONDS = 300;

  private final Map<String, Instant> store = new ConcurrentHashMap<>();
  private final long ttlSeconds;

  public InMemoryRequestIdStore() {
    this(DEFAULT_TTL_SECONDS);
  }

  public InMemoryRequestIdStore(long ttlSeconds) {
    this.ttlSeconds = ttlSeconds;
  }

  @Override
  public void register(String requestId) {
    if (requestId == null || requestId.isBlank())
      throw new IllegalArgumentException("RequestId cant be null");

    evictExpired();
    Instant expiry = Instant.now().plusSeconds(ttlSeconds); // fix: era plusMillis
    Instant existing = store.putIfAbsent(requestId, expiry);
    if (existing != null)
      throw new SecurityException("RequestId already present: " + requestId);

    log.debug("RequestId registrato: {} (scade: {})", requestId, expiry);
  }

  @Override
  public void consumeOrThrow(String requestId) {
    evictExpired();
    Instant expiry = store.remove(requestId);
    if (expiry == null)
      throw new SecurityException("RequestId non trovato o già usato: " + requestId);
    if (Instant.now().isAfter(expiry))
      throw new SecurityException("RequestId scaduto: " + requestId);

    log.debug("RequestId consumato: {}", requestId);
  }

  @Override
  public boolean isValid(String requestId) {
    Instant expiry = store.get(requestId);
    return expiry != null && Instant.now().isBefore(expiry);
  }

  @Override
  public int size() {
    return store.size();
  }

  private void evictExpired() {
    Instant now = Instant.now();
    Iterator<Map.Entry<String, Instant>> it = store.entrySet().iterator();
    int removed = 0;
    while (it.hasNext()) {
      if (now.isAfter(it.next().getValue())) {
        it.remove();
        removed++;
      }
    }
    if (removed > 0)
      log.debug("Rimossi {} requestId scaduti", removed);
  }
}