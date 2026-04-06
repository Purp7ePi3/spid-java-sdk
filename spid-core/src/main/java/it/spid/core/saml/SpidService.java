package it.spid.core.saml;

import it.spid.core.model.SpidConfig;
import it.spid.core.model.SpidLevel;
import it.spid.core.model.SpidUser;
import it.spid.crypto.XmlSigner;

/**
 * Facade principale della SDK SPID.
 * Punto di ingresso per tutte le operazioni SPID.
 */
public class SpidService {

  private final SpidConfig config;
  private final XmlSigner signer;

  /**
   * Costruttore senza firma — sign-requests: false.
   */
  public SpidService(SpidConfig config) {
    this(config, null);
  }

  /**
   * Costruttore con firma — sign-requests: true.
   * Il signer viene usato per firmare le AuthnRequest.
   */
  public SpidService(SpidConfig config, XmlSigner signer) {
    this.config = config;
    this.signer = config.isSignRequests() ? signer : null;
  }

  /**
   * Avvia il flusso di login SPID.
   * Se sign-requests: true, la AuthnRequest viene firmata digitalmente.
   */
  public LoginRequest initiateLogin(String idpEntityId, String idpSsoUrl, SpidLevel level) throws Exception {
    AuthnRequestBuilder builder = AuthnRequestBuilder.create(config)
        .forIdp(idpEntityId, idpSsoUrl)
        .withLevel(level != null ? level : config.getMinimumSpidLevel())
        .withSigner(signer);

    String redirectUrl = builder.buildRedirectUrl();
    String requestId = builder.getRequestId();

    return new LoginRequest(requestId, redirectUrl);
  }

  /**
   * Processa la SAMLResponse ricevuta dall'IdP sull'ACS endpoint.
   */
  public SpidUser processResponse(String samlResponseBase64, String expectedRequestId) throws Exception {
    String xml = SamlEncoder.decodeBase64(samlResponseBase64);
    return SamlResponseParser.parse(xml, expectedRequestId);
  }

  /**
   * Avvia il Single Logout SPID verso l'IdP.
   */
  public LogoutRequest initiateSingleLogout(String idpSloUrl, SpidUser user) throws Exception {
    LogoutRequestBuilder builder = LogoutRequestBuilder.create(config)
        .forIdp(idpSloUrl, user.getNameId(), user.getSessionIndex());

    String redirectUrl = builder.buildRedirectUrl();
    String requestId = builder.getRequestId();

    return new LogoutRequest(requestId, redirectUrl);
  }

  /**
   * Processa la LogoutResponse ricevuta dall'IdP.
   */
  public void processSingleLogoutResponse(String samlResponseBase64, String expectedRequestId) throws Exception {
    String xml = SamlEncoder.decodeBase64(samlResponseBase64);
    LogoutResponseParser.parse(xml, expectedRequestId);
  }

  public record LoginRequest(String requestId, String redirectUrl) {
  }

  public record LogoutRequest(String requestId, String redirectUrl) {
  }
}