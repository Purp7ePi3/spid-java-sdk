package it.spid.core.saml;

import it.spid.core.model.SpidConfig;
import it.spid.core.model.SpidLevel;
import it.spid.core.model.SpidUser;

/**
 * Facade principale della SDK SPID.
 * Punto di ingresso per tutte le operazioni SPID.
 */
public class SpidService {

  private final SpidConfig config;

  public SpidService(SpidConfig config) {
    this.config = config;
  }

  /**
   * Avvia il flusso di login SPID.
   *
   * @param idpEntityId EntityID dell'IdP scelto
   * @param idpSsoUrl   URL SSO dell'IdP
   * @param level       Livello SPID richiesto
   * @return LoginRequest con requestId e URL di redirect
   */
  public LoginRequest initiateLogin(String idpEntityId, String idpSsoUrl, SpidLevel level) throws Exception {
    AuthnRequestBuilder builder = AuthnRequestBuilder.create(config)
        .forIdp(idpEntityId, idpSsoUrl)
        .withLevel(level != null ? level : config.getMinimumSpidLevel());

    String redirectUrl = builder.buildRedirectUrl();
    String requestId = builder.getRequestId();

    return new LoginRequest(requestId, redirectUrl);
  }

  /**
   * Processa la SAMLResponse ricevuta dall'IdP sull'ACS endpoint.
   *
   * @param samlResponseBase64 SAMLResponse in Base64
   * @param expectedRequestId  ID della AuthnRequest originale
   * @return SpidUser con i dati dell'utente autenticato
   */
  public SpidUser processResponse(String samlResponseBase64, String expectedRequestId) throws Exception {
    String xml = SamlEncoder.decodeBase64(samlResponseBase64);
    return SamlResponseParser.parse(xml, expectedRequestId);
  }

  /**
   * Avvia il Single Logout SPID verso l'IdP.
   *
   * @param idpSloUrl URL SLO dell'IdP (dal suo metadata)
   * @param user      Utente da disconnettere (serve nameId e sessionIndex)
   * @return LogoutRequest con requestId e URL di redirect verso l'IdP
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
   *
   * @param samlResponseBase64 LogoutResponse in Base64 (GET binding) o XML
   *                           diretto
   * @param expectedRequestId  ID della LogoutRequest originale
   * @throws SecurityException se la risposta non è valida
   */
  public void processSingleLogoutResponse(String samlResponseBase64, String expectedRequestId) throws Exception {
    String xml = SamlEncoder.decodeBase64(samlResponseBase64);
    LogoutResponseParser.parse(xml, expectedRequestId);
  }

  // --- Record di risultato ---

  public record LoginRequest(String requestId, String redirectUrl) {
  }

  public record LogoutRequest(String requestId, String redirectUrl) {
  }
}