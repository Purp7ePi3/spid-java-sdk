package it.spid.core;

import it.spid.core.model.SpidConfig;
import it.spid.core.saml.LogoutRequestBuilder;
import it.spid.core.saml.LogoutResponseParser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class SingleLogoutTest {

  private SpidConfig config;

  @BeforeEach
  void setUp() {
    config = SpidConfig.builder()
        .entityId("https://miaapp.it")
        .assertionConsumerServiceUrl("https://miaapp.it/spid/acs")
        .singleLogoutServiceUrl("https://miaapp.it/spid/slo")
        .build();
  }

  @Test
  void logoutRequest_xmlContieneCampiObbligatori() throws Exception {
    String xml = LogoutRequestBuilder.create(config)
        .forIdp("https://idp.test.it/slo", "_nameId123", "_session456")
        .buildXml();

    assertNotNull(xml);
    assertTrue(xml.contains("LogoutRequest"));
    assertTrue(xml.contains("https://miaapp.it"));
    assertTrue(xml.contains("https://idp.test.it/slo"));
    assertTrue(xml.contains("_nameId123"));
    assertTrue(xml.contains("_session456"));
  }

  @Test
  void logoutRequest_idUnico() throws Exception {
    LogoutRequestBuilder b1 = LogoutRequestBuilder.create(config)
        .forIdp("https://idp.test.it/slo", "_n1", "_s1");
    LogoutRequestBuilder b2 = LogoutRequestBuilder.create(config)
        .forIdp("https://idp.test.it/slo", "_n2", "_s2");

    assertNotEquals(b1.getRequestId(), b2.getRequestId());
  }

  @Test
  void logoutRequest_senzaSessionIndex_xmlValido() throws Exception {
    String xml = LogoutRequestBuilder.create(config)
        .forIdp("https://idp.test.it/slo", "_nameId123", null)
        .buildXml();

    assertNotNull(xml);
    assertTrue(xml.contains("LogoutRequest"));
    assertFalse(xml.contains("SessionIndex"));
  }

  @Test
  void logoutResponse_successo_nonLanciaEccezione() {
    String xml = buildLogoutResponse("_req1", "urn:oasis:names:tc:SAML:2.0:status:Success");
    assertDoesNotThrow(() -> LogoutResponseParser.parse(xml, "_req1"));
  }

  @Test
  void logoutResponse_inResponseToErrato_lanciaEccezione() {
    String xml = buildLogoutResponse("_WRONG", "urn:oasis:names:tc:SAML:2.0:status:Success");
    assertThrows(SecurityException.class, () -> LogoutResponseParser.parse(xml, "_req1"));
  }

  @Test
  void logoutResponse_statusFallito_lanciaEccezione() {
    String xml = buildLogoutResponse("_req1", "urn:oasis:names:tc:SAML:2.0:status:Requester");
    assertThrows(SecurityException.class, () -> LogoutResponseParser.parse(xml, "_req1"));
  }

  @Test
  void logoutResponse_xmlMalformato_lanciaEccezione() {
    assertThrows(Exception.class, () -> LogoutResponseParser.parse("non-xml!!!", "_req1"));
  }

  private String buildLogoutResponse(String inResponseTo, String statusCode) {
    return """
        <?xml version="1.0" encoding="UTF-8"?>
        <samlp:LogoutResponse
            xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
            ID="_resp1"
            Version="2.0"
            IssueInstant="2026-01-01T00:00:00Z"
            InResponseTo="%s">
          <samlp:Status>
            <samlp:StatusCode Value="%s"/>
          </samlp:Status>
        </samlp:LogoutResponse>
        """.formatted(inResponseTo, statusCode);
  }
}