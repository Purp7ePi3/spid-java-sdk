package it.spid.spring.actuator;

import it.spid.metadata.IdpRegistry;
import it.spid.validator.RequestIdStore;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Endpoint(id = "spid")
public class SpidEndpoint {

  private final IdpRegistry idpRegistry;
  private final RequestIdStore requestIdStore;

  public SpidEndpoint(IdpRegistry idpRegistry, RequestIdStore requestIdStore) {
    this.idpRegistry = idpRegistry;
    this.requestIdStore = requestIdStore;
  }

  @ReadOperation
  public Map<String, Object> info() {
    Map<String, Object> idpCache = new LinkedHashMap<>();
    idpCache.put("valid", idpRegistry.isCacheValid());
    idpCache.put("idpCount", idpRegistry.size());
    idpCache.put("expiry", idpRegistry.getCacheExpiry());

    Map<String, Object> requests = new LinkedHashMap<>();
    requests.put("pentdingCount", requestIdStore.size());

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("status", idpRegistry.isCacheValid() ? "UP" : "DEGRADED");
    result.put("idpCache", idpCache);
    result.put("pendingRequests", requests);
    result.put("timestamp", Instant.now());

    return result;
  }
}
