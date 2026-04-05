package it.spid.core.saml;

import it.spid.core.model.SpidConfig;
import it.spid.core.model.SpidLevel;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * Costruisce la AuthnRequest SAML 2.0 per SPID.
 *
 * Uso:
 *   String xml = AuthnRequestBuilder.create(config)
 *       .forIdp("https://idp.example.it/metadata")
 *       .withLevel(SpidLevel.LEVEL_2)
 *       .buildXml();
 */
public class AuthnRequestBuilder {

    private final SpidConfig config;
    private String idpEntityId;
    private String idpSsoUrl;
    private SpidLevel spidLevel;
    private String requestId;

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

    public String getRequestId() {
        return requestId;
    }

    /**
     * Genera l'XML della AuthnRequest SPID-compliant.
     * Segue le specifiche AgID versione 1.2.
     */
    public String buildXml() {
        String issueInstant = DateTimeFormatter.ISO_INSTANT.format(Instant.now());

        return """
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
                spidLevel.getUri()
        );
    }

    /**
     * Genera il redirect URL per HTTP-Redirect binding (SAMLRequest in query string).
     */
    public String buildRedirectUrl() throws Exception {
        String xml = buildXml();
        String encoded = SamlEncoder.deflateAndEncode(xml);
        return idpSsoUrl + "?SAMLRequest=" + java.net.URLEncoder.encode(encoded, "UTF-8")
                + "&RelayState=" + requestId;
    }
}
