package it.spid.validator;

import it.spid.crypto.XmlSigner;
import it.spid.validator.SamlResponseValidator.ValidationResult;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class SamlSignatureValidationTest {

  private static final String ENTITY_ID = "https://miaapp.it";
  private static final String ACS_URL = "https://miaapp.it/spid/acs";
  private static final String REQUEST_ID = "_abc123";
  // ID dell'elemento root dell'XML — deve corrispondere all'attributo ID nel XML
  private static final String RESPONSE_ID = "_response1";

  private SamlResponseValidator validator;
  private KeyPair idpKeyPair;
  private X509Certificate idpCert;
  private String idpCertBase64;

  @BeforeAll
  static void setupSecurity() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @BeforeEach
  void setUp() throws Exception {
    validator = new SamlResponseValidator(
        new SamlResponseValidator.ValidationConfig(ENTITY_ID, ACS_URL));

    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    idpKeyPair = gen.generateKeyPair();
    idpCert = generateSelfSigned(idpKeyPair);
    idpCertBase64 = Base64.getEncoder().encodeToString(idpCert.getEncoded());
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
  void validate_xmlSenzaFirma_bloccaSullaFirma() {
    String xml = buildSamlResponse(REQUEST_ID, ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    ValidationResult result = validator.validate(xml, REQUEST_ID, idpCertBase64);
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream()
        .anyMatch(e -> e.contains("Firma digitale non valida") ||
            e.contains("firma") || e.contains("Firma")));
  }

  @Test
  void validate_firmaConChiaveDiversa_bloccaSullaFirma() throws Exception {
    // Firma con chiave alternativa ma valida
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair altKeyPair = gen.generateKeyPair();
    X509Certificate altCert = generateSelfSigned(altKeyPair);
    XmlSigner altSigner = new XmlSigner(altKeyPair.getPrivate(), altCert);

    String unsignedXml = buildSamlResponse(REQUEST_ID, ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    // Firma con RESPONSE_ID (l'ID del root element nell'XML)
    String signedXml = altSigner.sign(unsignedXml, RESPONSE_ID);

    // Valida con cert IdP originale — firma non corrisponde
    ValidationResult result = validator.validate(signedXml, REQUEST_ID, idpCertBase64);
    assertFalse(result.isValid());
    assertTrue(result.getErrors().stream()
        .anyMatch(e -> e.contains("Firma digitale non valida") ||
            e.contains("firma") || e.contains("Firma")));
  }

  @Test
  void validate_xmlFirmatoCorrettamente_superaControlloFirma() throws Exception {
    XmlSigner idpSigner = new XmlSigner(idpKeyPair.getPrivate(), idpCert);
    String unsignedXml = buildSamlResponse(REQUEST_ID, ACS_URL, ENTITY_ID,
        "urn:oasis:names:tc:SAML:2.0:status:Success",
        "2000-01-01T00:00:00Z", "2099-01-01T01:00:00Z");

    // Firma con RESPONSE_ID — l'ID del root element nell'XML
    String signedXml = idpSigner.sign(unsignedXml, RESPONSE_ID);

    ValidationResult result = validator.validate(signedXml, REQUEST_ID, idpCertBase64);
    // La firma è valida — gli errori non devono riguardare la firma
    assertTrue(result.isValid() ||
        result.getErrors().stream().noneMatch(e -> e.contains("Firma digitale non valida")));
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

  private X509Certificate generateSelfSigned(KeyPair keyPair) throws Exception {
    X500Name subject = new X500Name("CN=Test IdP, O=Test, C=IT");
    Instant now = Instant.now();

    var certBuilder = new JcaX509v3CertificateBuilder(
        subject,
        BigInteger.valueOf(System.currentTimeMillis()),
        Date.from(now),
        Date.from(now.plus(365, ChronoUnit.DAYS)),
        subject,
        keyPair.getPublic());

    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider("BC")
        .build(keyPair.getPrivate());

    return new JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(certBuilder.build(signer));
  }
}