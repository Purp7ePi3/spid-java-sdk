package it.spid.validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Previene i replay attack sulle SAMLResponse SPID.
 *
 * Un attaccante che intercetta una SAMLResponse valida potrebbe riusarla
 * per autenticarsi. Questo store tiene traccia dei requestId già processati
 * e rifiuta qualsiasi riuso.
 *
 * I requestId scadono automaticamente dopo {@code ttlSeconds} (default: 5
 * minuti)
 * per evitare memory leak in applicazioni long-running.
 *
 * Uso:
 * RequestIdStore store = new RequestIdStore();
 *
 * // Al login — registra il requestId
 * store.register(requestId);
 *
 * // All'ACS — verifica che non sia già stato usato
 * store.consumeOrThrow(requestId); // lancia SecurityException se replay
 */
public class RequestIdStore {

  private static final Logger log = LoggerFactory.getLogger(RequestIdStore.class);

  private final static long DEFAULT_TTL_SECONDS = 300;

  // requestId -> scandenza
  private final Map<String, Instant> store = new ConcurrentHashMap<>();
  private final long ttlSeconds;

  public RequestIdStore() {
    this(DEFAULT_TTL_SECONDS);
  }

  public RequestIdStore(long ttlSeconds) {
    this.ttlSeconds = ttlSeconds;
  }

  /**
   * Registra un requestId al momento dell'invio della AuthnRequest.
   * Se il requestId è già presente (caso anomalo), lancia eccezione.
   */
  public void register(String requestId) {
    if (requestId == null || requestId.isBlank()) {
      throw new IllegalArgumentException("RequestId cant be null");
    }
    evictExpired();
    Instant expiry = Instant.now().plusMillis(ttlSeconds);
    Instant existing = store.putIfAbsent(requestId, expiry);
    if (existing != null) {
      throw new SecurityException("RequestId already present, maybe attack" + requestId);
    }
    log.debug("RequestId registrato: {} (scade: {})", requestId, expiry);
  }

  /**
   * Consuma il requestId: verifica che esista, non sia scaduto, e lo rimuove.
   * Dopo questa chiamata il requestId non è più riusabile.
   *
   * @throws SecurityException se il requestId non esiste, è scaduto, o è già
   *                           stato consumato (replay)
   */
  public void consumeOrThrow(String requestId) {
    evictExpired();

    Instant expiry = store.remove(requestId);
    if (expiry == null) {
      throw new SecurityException(
          "RequestId non trovato o già usato — possibile replay attack: " + requestId);
    }
    if (Instant.now().isAfter(expiry)) {
      throw new SecurityException(
          "RequestId scaduto — la SAMLResponse è arrivata troppo tardi: " + requestId);
    }
    log.debug("RequestId consumato correttamente: {}", requestId);
  }

  /**
   * Verifica se un requestId è ancora valido (senza consumarlo).
   * Utile per debug e monitoring.
   */
  public boolean isValid(String requestId) {
    Instant expiry = store.get(requestId);
    return expiry != null && Instant.now().isBefore(expiry);
  }

  /**
   * Numero di requestId attualmente in store (inclusi eventuali scaduti non
   * ancora puliti).
   */
  public int size() {
    return this.store.size();
  }

  /**
   * Rimuove i requestId scaduti per evitare memory leak.
   * Viene chiamato automaticamente ad ogni operazione.
   */
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
    if (removed > 0) {
      log.debug("Rimossi {} requestId scaduti dallo store", removed);
    }
  }
}