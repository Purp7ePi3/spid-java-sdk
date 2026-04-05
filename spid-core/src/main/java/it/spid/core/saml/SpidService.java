package it.spid.core.saml;

import it.spid.core.model.SpidConfig;
import it.spid.core.model.SpidLevel;
import it.spid.core.model.SpidUser;

/**
 * Facade principale della SDK SPID.
 * Punto di ingresso per tutte le operazioni SPID.
 *
 * Esempio d'uso in Spring Boot:
 *
 *   SpidConfig config = SpidConfig.builder()
 *       .entityId("https://miaapp.it")
 *       .assertionConsumerServiceUrl("https://miaapp.it/spid/acs")
 *       .minimumSpidLevel(SpidLevel.LEVEL_2)
 *       .build();
 *
 *   SpidService spid = new SpidService(config);
 *
 *   // Login: genera redirect verso IdP
 *   String redirectUrl = spid.initiateLogin("https://idp.agid.gov.it/sso", SpidLevel.LEVEL_2);
 *   response.sendRedirect(redirectUrl);
 *
 *   // Callback: processa risposta IdP
 *   SpidUser user = spid.processResponse(samlResponse, requestId);
 */
public class SpidService {

    private final SpidConfig config;

    public SpidService(SpidConfig config) {
        this.config = config;
    }

    /**
     * Avvia il flusso di login SPID.
     * Restituisce l'URL a cui redirigere l'utente (verso l'IdP scelto).
     *
     * @param idpSsoUrl URL SSO dell'Identity Provider scelto dall'utente
     * @param level     Livello SPID richiesto (di default usa quello in config)
     * @return URL di redirect verso l'IdP
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
     * @param samlResponseBase64 SAMLResponse in Base64 (dal form POST dell'IdP)
     * @param expectedRequestId  ID della AuthnRequest originale (salvato in sessione)
     * @return SpidUser con i dati dell'utente autenticato
     */
    public SpidUser processResponse(String samlResponseBase64, String expectedRequestId) throws Exception {
        String xml = SamlEncoder.decodeBase64(samlResponseBase64);
        return SamlResponseParser.parse(xml, expectedRequestId);
    }

    /**
     * Risultato dell'inizializzazione del login.
     * Contiene il requestId da salvare in sessione e l'URL di redirect.
     */
    public record LoginRequest(String requestId, String redirectUrl) {}
}
