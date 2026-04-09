package it.spid.metadata;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Registry degli Identity Provider SPID ufficiali.
 *
 * Scarica il metadata federation da AgID, lo parsa, e lo cachea in memoria.
 * Il refresh avviene automaticamente ogni {@code cacheTtlHours} ore (default:
 * 24).
 *
 * Uso:
 * IdpRegistry registry = new IdpRegistry();
 * List<IdpInfo> idps = registry.getAll(); // lista completa
 * IdpInfo idp =
 * registry.findByEntityId("https://loginspid.aruba.it").orElseThrow();
 *
 * In Spring Boot il bean viene registrato automaticamente da
 * SpidAutoConfiguration.
 */
public class IdpRegistry {
  private final Logger log = LoggerFactory.getLogger(IdpRegistry.class);

  // URL ufficiale del metadata federation SPID (AgID)
  private static final String AGID_FEDERATION_URL = "https://registry.spid.gov.it/metadata/idp/spid-entities-idps.xml";

  private static final String MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata";
  private static final long DEFAULT_CACHE_TTL_HOURS = 24;

  private final String federationUrl;
  private final Long cacheTtlHours;
  private final HttpClient httpClient;

  // Cache
  private volatile List<IdpInfo> cachedIdps = Collections.emptyList();
  private volatile Instant cacheExpiry = Instant.MIN;

  public IdpRegistry() {
    this(AGID_FEDERATION_URL, DEFAULT_CACHE_TTL_HOURS);
  }

  public IdpRegistry(String federationUrl, long cacheTtlHours) {
    this.federationUrl = federationUrl;
    this.cacheTtlHours = cacheTtlHours;
    this.httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build();
  }

  /**
   * Restituisce la lista completa degli IdP SPID.
   * Usa la cache se ancora valida, altrimenti scarica da AgID.
   */
  public List<IdpInfo> getAll() {
    refreshIfNeeded();
    return Collections.unmodifiableList(cachedIdps);
  }

  /**
   * Trova un IdP per entityId.
   */
  public Optional<IdpInfo> findByEntityId(String entityId) {
    return getAll().stream()
        .filter(idp -> idp.getEntityId()
            .equals(entityId))
        .findFirst();
  }

  /**
   * Cerca IdP per nome (case-insensitive, ricerca parziale).
   */
  public List<IdpInfo> searchByName(String query) {
    String lowerQuery = query.toLowerCase();
    return getAll().stream()
        .filter(idp -> idp.getOrganizationName().toLowerCase().contains(lowerQuery))
        .toList();
  }

  /**
   * Forza il refresh della cache indipendentemente dalla scadenza.
   */
  public synchronized void refresh() {
    try {
      log.info("Download lista IdP SPID da AgID: {}", federationUrl);
      String xml = downloadFederation();
      List<IdpInfo> idps = parseFederation(xml);
      cachedIdps = idps;
      cacheExpiry = Instant.now().plus(Duration.ofHours(cacheTtlHours));
      log.info("Lista IdP aggiornata: {} provider trovati (prossimo refresh: {})",
          idps.size(), cacheExpiry);
    } catch (Exception e) {
      log.error("Errore nel download lista IdP da AgID: {}", e.getMessage());
      // Mantieni la cache precedente se disponibile
      if (cachedIdps.isEmpty()) {
        log.warn("Cache vuota e download fallito — nessun IdP disponibile");
      } else {
        log.warn("Uso cache precedente ({} IdP)", cachedIdps.size());
        // Estendi la cache per evitare retry continui
        cacheExpiry = Instant.now().plus(Duration.ofMinutes(5));
      }
    }
  }

  /**
   * Numero di IdP in cache.
   */
  public int size() {
    return cachedIdps.size();
  }

  /**
   * Indica se la cache è attualmente valida.
   */
  public boolean isCacheValid() {
    return !cachedIdps.isEmpty() && Instant.now().isBefore(cacheExpiry);
  }

  private void refreshIfNeeded() {
    if (!isCacheValid()) {
      refresh();
    }
  }

  private String downloadFederation() throws Exception {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(federationUrl))
        .timeout(Duration.ofSeconds(25))
        .GET()
        .build();

    HttpResponse<String> response = httpClient.send(request,
        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));

    if (response.statusCode() != 200) {
      throw new RuntimeException("HTTP " + response.statusCode() + " dal registry AgID");
    }

    return response.body();
  }

  private List<IdpInfo> parseFederation(String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newDefaultInstance();
    factory.setNamespaceAware(true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

    Document doc = factory.newDocumentBuilder()
        .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

    List<IdpInfo> idps = new ArrayList<>();
    NodeList entryDescriptors = doc.getElementsByTagNameNS(MD_NS, "EntityDescriptor");

    for (int i = 0; i < entryDescriptors.getLength(); i++) {
      Element entity = (Element) entryDescriptors.item(i);
      try {
        IdpInfo idp = parseEntityDescriptor(entity);
        if (idp != null) {
          idps.add(idp);
        }
      } catch (Exception e) {
        log.warn("Errore nel parsing EntityDescriptor {}: {}", i, e.getMessage());
      }
    }
    return idps;
  }

  private IdpInfo parseEntityDescriptor(Element entity) {
    // Solo IDPSSODescriptor — salta gli SP
    NodeList idpDescriptors = entity.getElementsByTagNameNS(MD_NS, "IDPSSODescriptor");
    if (idpDescriptors.getLength() == 0)
      return null;
    String entityId = entity.getAttribute("entityID");
    String orgName = extractOrganizationName(entity);
    String ssoUrl = extractServiceUrl(entity, "SingleSignOnService");
    String sloUrl = extractServiceUrl(entity, "SingleLogoutService");
    String certBase64 = extractCertificate(entity);
    String logoUrl = extractLogoUrl(entity);

    return new IdpInfo(entityId, orgName, ssoUrl, sloUrl, certBase64, logoUrl);
  }

  private String extractOrganizationName(Element entity) {
    NodeList nodes = entity.getElementsByTagNameNS(MD_NS, "OrganizationDisplayName");
    if (nodes.getLength() > 0) {
      return nodes.item(0).getTextContent().trim();
    }
    nodes = entity.getElementsByTagNameNS(MD_NS, "OrganizationName");
    if (nodes.getLength() > 0) {
      return nodes.item(0).getTextContent().trim();
    }
    return entity.getAttribute("entityId");
  }

  private String extractServiceUrl(Element entity, String serviceName) {
    NodeList nodes = entity.getElementsByTagNameNS(MD_NS, serviceName);
    String redirectUrl = null;
    for (int i = 0; i < nodes.getLength(); i++) {
      Element el = (Element) nodes.item(i);
      String binding = el.getAttribute("Binding");
      String location = el.getAttribute("Location");
      if (binding.contains("HTTP-POST"))
        return location;
      if (binding.contains("HTTP-Redirect"))
        redirectUrl = location;
    }
    return redirectUrl;
  }

  private String extractCertificate(Element entity) {
    NodeList nodes = entity.getElementsByTagName("ds:X509Certificate");
    if (nodes.getLength() == 0) {
      // Prova senza prefisso namespace
      nodes = entity.getElementsByTagNameNS(
          "http://www.w3.org/2000/09/xmldsig#", "X509Certificate");
    }
    if (nodes.getLength() > 0) {
      return nodes.item(0).getTextContent().replaceAll("\\s", "");
    }
    return null;
  }

  private String extractLogoUrl(Element entity) {
    // Il logo è tipicamente in un'estensione UI Info
    NodeList nodes = entity.getElementsByTagNameNS(
        "urn:oasis:names:tc:SAML:metadata:ui", "Logo");
    if (nodes.getLength() > 0) {
      return nodes.item(0).getTextContent().trim();
    }
    return null;
  }

  public Instant getCacheExpiry() {
    return cacheExpiry;
  }
}
