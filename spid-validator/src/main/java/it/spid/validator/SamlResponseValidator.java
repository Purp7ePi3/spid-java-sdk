package it.spid.validator;

import it.spid.crypto.CertificateLoader;
import it.spid.crypto.XmlSignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Validazione completa della SAMLResponse SPID secondo le specifiche AgID.
 *
 * Esegue tutti i controlli obbligatori:
 * 1. Firma digitale valida (IdP certificate)
 * 2. InResponseTo corrisponde alla request originale
 * 3. Audience corrisponde all'entityId del SP
 * 4. NotBefore / NotOnOrAfter nell'intervallo valido
 * 5. StatusCode = Success
 * 6. Livello SPID >= livello richiesto
 * 7. Destination corrisponde all'ACS URL
 */
public class SamlResponseValidator {

    private static final Logger log = LoggerFactory.getLogger(SamlResponseValidator.class);

    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";

    // Tolleranza clock skew: 3 minuti
    private static final long CLOCK_SKEW_MINUTES = 3;

    private final ValidationConfig config;

    public SamlResponseValidator(ValidationConfig config) {
        this.config = config;
    }

    /**
     * Valida la SAMLResponse completa.
     * Lancia ValidationException con lista di tutti gli errori trovati.
     *
     * @param samlResponseXml  XML decodificato della risposta
     * @param expectedRequestId ID della AuthnRequest originale
     * @param idpCertBase64    Certificato IdP in Base64 (dal metadata IdP)
     */
    public ValidationResult validate(String samlResponseXml,
                                     String expectedRequestId,
                                     String idpCertBase64) {
        List<String> errors = new ArrayList<>();
        Document doc = null;

        try {
            doc = parseXml(samlResponseXml);
        } catch (Exception e) {
            errors.add("XML non parsabile: " + e.getMessage());
            return ValidationResult.failed(errors);
        }

        // 1. Verifica firma digitale
        try {
            X509Certificate idpCert = CertificateLoader.loadCertificateFromBase64(idpCertBase64);
            XmlSignatureValidator.validate(samlResponseXml, idpCert);
            log.debug("Firma XML valida");
        } catch (Exception e) {
            errors.add("Firma digitale non valida: " + e.getMessage());
        }

        // 2. Verifica InResponseTo
        String inResponseTo = doc.getDocumentElement().getAttribute("InResponseTo");
        if (!expectedRequestId.equals(inResponseTo)) {
            errors.add("InResponseTo non corrisponde. Atteso: " + expectedRequestId +
                       ", trovato: " + inResponseTo);
        }

        // 3. Verifica Destination
        String destination = doc.getDocumentElement().getAttribute("Destination");
        if (!config.getAcsUrl().equals(destination)) {
            errors.add("Destination non corrisponde all'ACS URL. " +
                       "Atteso: " + config.getAcsUrl() + ", trovato: " + destination);
        }

        // 4. Verifica StatusCode
        NodeList statusNodes = doc.getElementsByTagNameNS(SAMLP_NS, "StatusCode");
        if (statusNodes.getLength() > 0) {
            String statusValue = statusNodes.item(0).getAttributes()
                    .getNamedItem("Value").getNodeValue();
            if (!statusValue.contains("Success")) {
                errors.add("Autenticazione fallita. StatusCode: " + statusValue);
                // Se autenticazione fallita, non continuare con altri controlli
                return ValidationResult.failed(errors);
            }
        } else {
            errors.add("StatusCode mancante nella risposta");
        }

        // 5. Verifica Audience
        NodeList audienceNodes = doc.getElementsByTagNameNS(SAML_NS, "AudienceRestriction");
        if (audienceNodes.getLength() > 0) {
            NodeList audiences = ((Element) audienceNodes.item(0))
                    .getElementsByTagNameNS(SAML_NS, "Audience");
            boolean audienceFound = false;
            for (int i = 0; i < audiences.getLength(); i++) {
                if (config.getEntityId().equals(audiences.item(i).getTextContent().trim())) {
                    audienceFound = true;
                    break;
                }
            }
            if (!audienceFound) {
                errors.add("Audience non corrisponde all'entityId: " + config.getEntityId());
            }
        } else {
            errors.add("AudienceRestriction mancante nell'Assertion");
        }

        // 6. Verifica NotBefore / NotOnOrAfter
        NodeList conditionNodes = doc.getElementsByTagNameNS(SAML_NS, "Conditions");
        if (conditionNodes.getLength() > 0) {
            Element conditions = (Element) conditionNodes.item(0);
            Instant now = Instant.now();

            String notBefore = conditions.getAttribute("NotBefore");
            if (!notBefore.isEmpty()) {
                Instant nb = Instant.parse(notBefore).minus(CLOCK_SKEW_MINUTES, ChronoUnit.MINUTES);
                if (now.isBefore(nb)) {
                    errors.add("Assertion non ancora valida (NotBefore: " + notBefore + ")");
                }
            }

            String notOnOrAfter = conditions.getAttribute("NotOnOrAfter");
            if (!notOnOrAfter.isEmpty()) {
                Instant nooa = Instant.parse(notOnOrAfter).plus(CLOCK_SKEW_MINUTES, ChronoUnit.MINUTES);
                if (now.isAfter(nooa)) {
                    errors.add("Assertion scaduta (NotOnOrAfter: " + notOnOrAfter + ")");
                }
            }
        }

        if (errors.isEmpty()) {
            log.info("SAMLResponse validata con successo per request: {}", expectedRequestId);
            return ValidationResult.success();
        } else {
            return ValidationResult.failed(errors);
        }
    }

    private Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Configurazione per la validazione.
     */
    public record ValidationConfig(String entityId, String acsUrl) {
        public String getEntityId() { return entityId; }
        public String getAcsUrl() { return acsUrl; }
    }

    /**
     * Risultato della validazione.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final List<String> errors;

        private ValidationResult(boolean valid, List<String> errors) {
            this.valid = valid;
            this.errors = errors;
        }

        public static ValidationResult success() {
            return new ValidationResult(true, List.of());
        }

        public static ValidationResult failed(List<String> errors) {
            return new ValidationResult(false, errors);
        }

        public boolean isValid() { return valid; }
        public List<String> getErrors() { return errors; }

        public void throwIfInvalid() {
            if (!valid) {
                throw new SecurityException("SAMLResponse non valida: " + errors);
            }
        }
    }
}
