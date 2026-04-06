package it.spid.validator;

import it.spid.validator.SamlResponseValidator.ValidationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test per SamlResponseValidator.
 * Con la nuova logica la firma è obbligatoria — se il cert è assente o non
 * valido
 * il validator blocca subito senza arrivare agli altri controlli.
 */
public class SamlResponseValidatorTest {

  private static final String ENTITY_ID = "https://miaapp.it";
  private static final String ACS_URL = "https://miaapp.it/spid/acs";
  private static final String REQUEST_ID = "_abc123";

  private SamlResponseValidator validator;

  @BeforeEach
  void setUp() {
    validator = new SamlResponseValidator(
        new SamlResponseValidator.ValidationConfig(ENTITY_ID, ACS_URL));
  }

  @Test
  void validate_xmlNonParsabile_restituisceErrore() {
    ValidationResult result = validator.validate("non-xml-!!!", REQUEST_ID, null);
    assertFalse(result.isValid());
    assertFalse(result.getErrors().isEmpty());
  }

  @Test
  void validate_certMancante_bloccaSubito() {
    String xml = buildSamlResponse(REQUEST_ID, ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    ValidationResult result = validator.validate(xml, REQUEST_ID, null);
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream()
        .anyMatch(e -> e.contains("Certificato IdP mancante")));
  }

  @Test
  void validate_certVuoto_bloccaSubito() {
    String xml = buildSamlResponse(REQUEST_ID, ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    ValidationResult result = validator.validate(xml, REQUEST_ID, "  ");
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream()
        .anyMatch(e -> e.contains("Certificato IdP mancante")));
  }

  @Test
  void validate_certNonValido_bloccaSullaFirma() {
    String xml = buildSamlResponse(REQUEST_ID, ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    ValidationResult result = validator.validate(xml, REQUEST_ID, "AAAA");
    assertFalse(result.isValid());
    assertFalse(result.getErrors().isEmpty());
  }

  @Test
  void validate_xmlSenzaFirma_bloccaSullaFirma() {
    String xml = buildSamlResponse(REQUEST_ID, ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    String fakeCert = java.util.Base64.getEncoder()
        .encodeToString("not-a-real-cert".getBytes());
    ValidationResult result = validator.validate(xml, REQUEST_ID, fakeCert);
    assertFalse(result.isValid());
    assertFalse(result.getErrors().isEmpty());
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
        """.formatted(inResponseTo, destination, statusCode,
        notBefore, notOnOrAfter, audience);
  }
}