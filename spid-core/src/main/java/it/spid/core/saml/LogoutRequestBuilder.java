package it.spid.core.saml;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import it.spid.core.model.SpidConfig;

/**
 * Costruisce la LogoutRequest SAML 2.0 per il Single Logout SPID.
 *
 * Uso:
 * String redirectUrl = LogoutRequestBuilder.create(config)
 * .forIdp("https://idp.example.it/slo", nameId, sessionIndex)
 * .buildRedirectUrl();
 */
public class LogoutRequestBuilder {
  private final SpidConfig config;
  private String idpSloUrl;
  private String nameId;
  private String sessionIndex;
  private final String requestId;

  private LogoutRequestBuilder(SpidConfig config) {
    this.config = config;
    this.requestId = "_" + UUID.randomUUID().toString().replace("-", "");
  }

  public static LogoutRequestBuilder create(SpidConfig config) {
    return new LogoutRequestBuilder(config);
  }

  public LogoutRequestBuilder forIdp(String idpString, String nameId, String sessionIndex) {
    this.idpSloUrl = idpString;
    this.nameId = nameId;
    this.sessionIndex = sessionIndex;
    return this;
  }

  public String getRequestId() {
    return this.requestId;
  }

  public String buildXml() {
    String issueInstant = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
    String sessionIndexBlock = sessionIndex != null
        ? "<samlp:SessionIndex>%s</samlp:SessionIndex>".formatted(sessionIndex)
        : "";
    return """
        <?xml version="1.0" encoding="UTF-8"?>
        <samlp:LogoutRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="%s"
            Version="2.0"
            IssueInstant="%s"
            Destination="%s">
          <saml:Issuer
              Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
            %s
          </saml:Issuer>
          <saml:NameID
              Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
            %s
          </saml:NameID>
          %s
        </samlp:LogoutRequest>
        """.formatted(
        requestId,
        issueInstant,
        idpSloUrl,
        config.getEntityId(),
        nameId,
        sessionIndexBlock);
  }

  /**
   * Genera il redirect URL per HTTP-Redirect binding.
   */
  public String buildRedirectUrl() throws Exception {
    String xml = buildXml();
    String encoded = SamlEncoder.decodeAndInflate(xml);
    return idpSloUrl + "?SAMLRequest=" + java.net.URLEncoder.encode(encoded, "UTF-8")
        + "&RelayState=" + requestId;
  }
}
