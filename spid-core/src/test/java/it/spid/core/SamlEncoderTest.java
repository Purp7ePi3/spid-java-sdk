package it.spid.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

import it.spid.core.saml.SamlEncoder;

public class SamlEncoderTest {
  private static final String XML = """
      <?xml version="1.0" encoding="UTF-8"?>
      <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
          ID="_test123">
        <saml:Issuer>https://miaapp.it</saml:Issuer>
      </samlp:AuthnRequest>
      """;

  @Test
  void deflateAndEncode_produceNotEmptyString() throws Exception {
    String encode = SamlEncoder.deflateAndEncode(XML);
    assertNotNull(encode);
    assertFalse(encode.isBlank());
  }

  @Test
  void decodeAndInflate_FlipDeflateAndEncode() throws Exception {
    String encoded = SamlEncoder.deflateAndEncode(XML);
    String decoded = SamlEncoder.decodeAndInflate(encoded);
    assertEquals(XML, decoded);
  }

  @Test
  void DecodeBase64() {
    String original = "Hello Spid";
    String base64 = java.util.Base64.getEncoder()
        .encodeToString(original.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    assertEquals(original, SamlEncoder.decodeBase64(base64));
  }
}
