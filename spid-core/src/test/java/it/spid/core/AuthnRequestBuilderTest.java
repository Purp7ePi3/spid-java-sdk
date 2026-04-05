package it.spid.core;

import it.spid.core.model.SpidConfig;
import it.spid.core.model.SpidLevel;
import it.spid.core.saml.AuthnRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class AuthnRequestBuilderTest {
  private SpidConfig config;

  @BeforeEach
  void setUp() {
    config = SpidConfig.builder()
        .entityId("https://miaapp.it")
        .assertionConsumerServiceUrl("https://miaapp.it/spid/acs")
        .minimumSpidLevel(SpidLevel.LEVEL_2)
        .build();
  }

  @Test
  void buildXml_MandatoryFields() throws Exception {
    String xml = AuthnRequestBuilder.create(config)
        .forIdp("https://idp.test.it", "https://idp.test.it/sso")
        .withLevel(SpidLevel.LEVEL_2)
        .buildXml();

    assertNotNull(xml);
    assertTrue(xml.contains("AuthnRequest"));
    assertTrue(xml.contains("https://miaapp.it"));
    assertTrue(xml.contains("https://miaapp.it/spid/acs"));
    assertTrue(xml.contains("https://www.spid.gov.it/SpidL2"));
    assertTrue(xml.contains("ForceAuthn=\"true\""));
  }

  @Test
  void buildXml_requestUniqId() throws Exception {
    AuthnRequestBuilder b1 = AuthnRequestBuilder.create(config)
        .forIdp("https://idp.test.it", "https://idp.test.it/sso");
    AuthnRequestBuilder b2 = AuthnRequestBuilder.create(config)
        .forIdp("https://idp.test.it", "https://idp.test.it/sso");

    assertNotEquals(b1.getRequestId(), b2.getRequestId());
  }

  @Test
  void SpidConfig_MandatoryEntityId() {
    assertThrows(IllegalStateException.class, () -> SpidConfig.builder()
        .assertionConsumerServiceUrl("https://miaapp.it/acs")
        .build());
  }
}
