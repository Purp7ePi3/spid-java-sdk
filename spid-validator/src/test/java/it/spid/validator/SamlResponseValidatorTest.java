package it.spid.validator;

import it.spid.validator.SamlResponseValidator.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test per SamlResponseValidator.
 * Usa XML sintetici per coprire i casi di validazione strutturale
 * (la verifica firma richiede un certificato reale e viene testata
 * separatamente).
 */
public class SamlResponseValidatorTest {

  private static final String ENTITY_ID = "https://miaapp.it";
  private static final String ACS_URL = "https://miaapp.it/spid/acs";
  private static final String REQUEST_ID = "_abc123";
  // Certificato fittizio in Base64 (non valido crittograficamente — usato per
  // test strutturali)
  private static final String FAKE_CERT_B64 = "AAAA";

  private SamlResponseValidator validator;

  @BeforeEach
  void setUp() {
    validator = new SamlResponseValidator(
        new SamlResponseValidator.ValidationConfig(ENTITY_ID, ACS_URL));
  }

  @Test
  void validate_xmlNonParsabile_restituisceErrore() {
    ValidationResult result = validator.validate("non-xml-!!!", REQUEST_ID, FAKE_CERT_B64);
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream().anyMatch(e -> e.contains("XML non parsabile")));
  }

  @Test
  void validate_statusCodeFallito_restituisceErrore() {
    String xml = buildSamlResponse(REQUEST_ID, ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
        "2099-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    ValidationResult result = validator.validate(xml, REQUEST_ID, FAKE_CERT_B64);
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream().anyMatch(e -> e.contains("StatusCode")));
  }

  @Test
  void validate_inResponseToErrato_restituisceErrore() {
    String xml = buildSamlResponse("_WRONG_ID", ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    ValidationResult result = validator.validate(xml, REQUEST_ID, FAKE_CERT_B64);
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream().anyMatch(e -> e.contains("InResponseTo")));
  }

  @Test
  void validate_destinationErrata_restituisceErrore() {
    String xml = buildSamlResponse(REQUEST_ID, "https://altro.it/acs", ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    ValidationResult result = validator.validate(xml, REQUEST_ID, FAKE_CERT_B64);
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream().anyMatch(e -> e.contains("Destination")));
  }

  @Test
  void validate_audienceErrata_restituisceErrore() {
    String xml = buildSamlResponse(REQUEST_ID, ACS_URL, "https://altro.it",
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    ValidationResult result = validator.validate(xml, REQUEST_ID, FAKE_CERT_B64);
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream().anyMatch(e -> e.contains("Audience")));
  }

  @Test
  void validate_assertionScaduta_restituisceErrore() {
    String xml = buildSamlResponse(REQUEST_ID, ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2000-01-01T01:00:00Z"); // scaduta nel 2000

    ValidationResult result = validator.validate(xml, REQUEST_ID, FAKE_CERT_B64);
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream().anyMatch(e -> e.contains("scaduta")));
  }

  @Test
  void validationResult_throwIfInvalid_lanciaEccezione() {
    ValidationResult result = ValidationResult.failed(java.util.List.of("Errore test"));
    assertThrows(SecurityException.class, result::throwIfInvalid);
  }

  @Test
  void validationResult_success_nonLanciaEccezione() {
    ValidationResult result = ValidationResult.success();
    assertTrue(result.isValid());
    assertDoesNotThrow(result::throwIfInvalid);
  }

  // Helper: costruisce una SAMLResponse XML minimale per i test
  private String buildSamlResponse(String inResponseTo, String destination,
      String audience, String statusCode,
      String notBefore, String notOnOrAfter) {
    return """
        <?xml version="1.0" encoding="UTF-8"?>
        <samlp:Response
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="_response1"
            InResponseTo="%s"
            Destination="%s"
            Version="2.0"
            IssueInstant="2026-01-01T00:00:00Z">
          <samlp:Status>
            <samlp:StatusCode Value="%s"/>
          </samlp:Status>
          <saml:Assertion ID="_assertion1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
            <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
              <saml:AudienceRestriction>
                <saml:Audience>%s</saml:Audience>
              </saml:AudienceRestriction>
            </saml:Conditions>
          </saml:Assertion>
        </samlp:Response>
        """.formatted(inResponseTo, destination, statusCode, notBefore, notOnOrAfter, audience);
  }
}