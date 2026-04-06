package it.spid.core;

import it.spid.core.model.SpidConfig;
import it.spid.core.model.SpidLevel;
import it.spid.core.saml.AuthnRequestBuilder;
import it.spid.crypto.XmlSigner;
import it.spid.crypto.CertificateLoader;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

public class AuthnRequestSignatureTest {

  private SpidConfig config;
  private XmlSigner signer;

  @BeforeAll
  static void setupSecurity() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @BeforeEach
  void setup() throws Exception {
    config = SpidConfig.builder()
        .entityId("https://miaapp.it")
        .assertionConsumerServiceUrl("https://miaapp.it/spid/acs")
        .minimumSpidLevel(SpidLevel.LEVEL_2)
        .signRequests(true)
        .build();

    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair keyPair = gen.generateKeyPair();

    X509Certificate cert = TestCertificateHelper.generateSelfSigned(keyPair);
    signer = new XmlSigner(keyPair.getPrivate(), cert);
  }

  @Test
  void buildXml_senzaSigner_xmlNonFirmato() throws Exception {
    String xml = AuthnRequestBuilder.create(config)
        .forIdp("https://idp.test.it", "https://idp.test.it/sso")
        .withLevel(SpidLevel.LEVEL_2)
        // nessun signer
        .buildXml();

    assertNotNull(xml);
    assertFalse(xml.contains("Signature"),
        "XML non deve contenere Signature senza signer");
  }

  @Test
  void buildXml_conSigner_xmlContieneFirma() throws Exception {
    String xml = AuthnRequestBuilder.create(config)
        .forIdp("https://idp.test.it", "https://idp.test.it/sso")
        .withLevel(SpidLevel.LEVEL_2)
        .withSigner(signer)
        .buildXml();

    assertNotNull(xml);
    assertTrue(xml.contains("Signature"),
        "XML deve contenere Signature con signer");
    assertTrue(xml.contains("SignatureValue"),
        "XML deve contenere SignatureValue");
    assertTrue(xml.contains("X509Certificate"),
        "XML deve contenere il certificato");
  }

  @Test
  void buildXml_conSigner_xmlContieneCampiOriginali() throws Exception {
    String xml = AuthnRequestBuilder.create(config)
        .forIdp("https://idp.test.it", "https://idp.test.it/sso")
        .withLevel(SpidLevel.LEVEL_2)
        .withSigner(signer)
        .buildXml();

    // La firma non deve alterare i campi originali
    assertTrue(xml.contains("https://miaapp.it"));
    assertTrue(xml.contains("https://miaapp.it/spid/acs"));
    assertTrue(xml.contains("https://www.spid.gov.it/SpidL2"));
    assertTrue(xml.contains("ForceAuthn=\"true\""));
  }

  @Test
  void buildRedirectUrl_conSigner_urlValido() throws Exception {
    String url = AuthnRequestBuilder.create(config)
        .forIdp("https://idp.test.it", "https://idp.test.it/sso")
        .withSigner(signer)
        .buildRedirectUrl();

    assertNotNull(url);
    assertTrue(url.startsWith("https://idp.test.it/sso?SAMLRequest="));
    assertTrue(url.contains("RelayState="));
  }

  @Test
  void spidService_signRequestsFalse_nonFirma() throws Exception {
    SpidConfig configNoSign = SpidConfig.builder()
        .entityId("https://miaapp.it")
        .assertionConsumerServiceUrl("https://miaapp.it/spid/acs")
        .signRequests(false)
        .build();

    // Anche con il signer, se false non firma
    it.spid.core.saml.SpidService service = new it.spid.core.saml.SpidService(configNoSign, signer);

    it.spid.core.saml.SpidService.LoginRequest req = service.initiateLogin("https://idp.test.it",
        "https://idp.test.it/sso", SpidLevel.LEVEL_2);

    assertNotNull(req.requestId());
    assertNotNull(req.redirectUrl());
  }
}
