package it.spid.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import it.spid.validator.RequestIdStore;

import java.time.Duration;

public class RedisRequestIdStore implements RequestIdStore {

  private static final Logger log = LoggerFactory.getLogger(RedisRequestIdStore.class);
  private static final String PREFIX = "spid:requestid:";
  private static final long DEFAULT_TTL_SECONDS = 300;

  private final StringRedisTemplate redis;
  private final long ttlSeconds;

  public RedisRequestIdStore(StringRedisTemplate redis) {
    this(redis, DEFAULT_TTL_SECONDS);
  }

  public RedisRequestIdStore(StringRedisTemplate redis, long ttlSeconds) {
    this.redis = redis;
    this.ttlSeconds = ttlSeconds;
  }

  @Override
  public void register(String requestId) {
    if (requestId == null || requestId.isBlank())
      throw new IllegalArgumentException("RequestId cant be null");

    String key = PREFIX + requestId;
    // setIfAbsent = SET NX EX — atomico, sicuro in cluster
    Boolean inserted = redis.opsForValue()
        .setIfAbsent(key, "1", Duration.ofSeconds(ttlSeconds));

    if (Boolean.FALSE.equals(inserted))
      throw new SecurityException("RequestId already present: " + requestId);

    log.debug("RequestId registrato su Redis: {}", requestId);
  }

  @Override
  public void consumeOrThrow(String requestId) {
    String key = PREFIX + requestId;
    Boolean deleted = redis.delete(key);
    if (Boolean.FALSE.equals(deleted) || deleted == null)
      throw new SecurityException("RequestId non trovato o già usato: " + requestId);

    log.debug("RequestId consumato da Redis: {}", requestId);
  }

  @Override
  public boolean isValid(String requestId) {
    return Boolean.TRUE.equals(redis.hasKey(PREFIX + requestId));
  }

  @Override
  public int size() {
    // costoso, solo per debug/monitoring
    var keys = redis.keys(PREFIX + "*");
    return keys == null ? 0 : keys.size();
  }
}