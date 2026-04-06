package it.spid.core.saml;

import it.spid.core.model.SpidConfig;
import it.spid.core.model.SpidLevel;
import it.spid.crypto.XmlSigner;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * Costruisce la AuthnRequest SAML 2.0 per SPID.
 *
 * Se viene fornito un XmlSigner, la request viene firmata digitalmente
 * prima dell'encoding (richiesto da AgID quando sign-requests: true).
 *
 * Uso:
 * String xml = AuthnRequestBuilder.create(config)
 * .forIdp("https://idp.example.it/metadata", "https://idp.example.it/sso")
 * .withLevel(SpidLevel.LEVEL_2)
 * .withSigner(xmlSigner) // opzionale
 * .buildXml();
 */
public class AuthnRequestBuilder {

  private final SpidConfig config;
  private String idpEntityId;
  private String idpSsoUrl;
  private SpidLevel spidLevel;
  private final String requestId;
  private XmlSigner signer;

  private AuthnRequestBuilder(SpidConfig config) {
    this.config = config;
    this.requestId = "_" + UUID.randomUUID().toString().replace("-", "");
    this.spidLevel = config.getMinimumSpidLevel();
  }

  public static AuthnRequestBuilder create(SpidConfig config) {
    return new AuthnRequestBuilder(config);
  }

  public AuthnRequestBuilder forIdp(String idpEntityId, String idpSsoUrl) {
    this.idpEntityId = idpEntityId;
    this.idpSsoUrl = idpSsoUrl;
    return this;
  }

  public AuthnRequestBuilder withLevel(SpidLevel level) {
    this.spidLevel = level;
    return this;
  }

  /**
   * Imposta il signer per la firma digitale della AuthnRequest.
   * Se null, la request non viene firmata.
   */
  public AuthnRequestBuilder withSigner(XmlSigner signer) {
    this.signer = signer;
    return this;
  }

  public String getRequestId() {
    return requestId;
  }

  /**
   * Genera l'XML della AuthnRequest SPID-compliant.
   * Se è stato impostato un signer, l'XML viene firmato.
   */
  public String buildXml() throws Exception {
    String issueInstant = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

    String xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <samlp:AuthnRequest
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="%s"
            Version="2.0"
            IssueInstant="%s"
            Destination="%s"
            AssertionConsumerServiceURL="%s"
            AssertionConsumerServiceIndex="0"
            AttributeConsumingServiceIndex="0"
            ForceAuthn="true">
          <saml:Issuer
              NameQualifier="%s"
              Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">
            %s
          </saml:Issuer>
          <samlp:NameIDPolicy
              Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
          <samlp:RequestedAuthnContext Comparison="minimum">
            <saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>
          </samlp:RequestedAuthnContext>
        </samlp:AuthnRequest>
        """.formatted(
        requestId,
        issueInstant,
        idpSsoUrl,
        config.getAssertionConsumerServiceUrl(),
        config.getEntityId(),
        config.getEntityId(),
        spidLevel.getUri());

    // Firma l'XML se è stato configurato un signer
    if (signer != null) {
      xml = signer.sign(xml, requestId);
    }

    return xml;
  }

  /**
   * Genera il redirect URL per HTTP-Redirect binding.
   * NOTA: per HTTP-Redirect binding con firma, la firma va sulla query string
   * (non embedded nell'XML). Per ora usiamo POST binding quando sign-requests:
   * true.
   */
  public String buildRedirectUrl() throws Exception {
    String xml = buildXml();
    String encoded = SamlEncoder.deflateAndEncode(xml);
    return idpSsoUrl + "?SAMLRequest=" + java.net.URLEncoder.encode(encoded, "UTF-8")
        + "&RelayState=" + requestId;
  }

  /**
   * Genera l'XML firmato in Base64 per HTTP-POST binding.
   * Usato quando sign-requests: true — la firma è embedded nell'XML.
   */
  public String buildPostBase64() throws Exception {
    String xml = buildXml();
    return java.util.Base64.getEncoder().encodeToString(
        xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }
}