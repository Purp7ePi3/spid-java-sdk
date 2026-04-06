package it.spid.core.saml;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * Parsa la LogoutResponse ricevuta dall'IdP dopo il Single Logout.
 *
 * Valida che:
 * - InResponseTo corrisponda alla LogoutRequest originale
 * - StatusCode sia Success
 */
public class LogoutResponseParser {

  private static final String SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";

  private LogoutResponseParser() {
  }

  /**
   * Parsa e valida la LogoutResponse.
   *
   * @param samlResponseXml   XML della risposta (già decodificata)
   * @param expectedRequestId ID della LogoutRequest originale
   * @throws SecurityException se la risposta non è valida
   */
  public static void parse(String samlResponseXml, String expectedRequestId) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

    Document doc = factory.newDocumentBuilder()
        .parse(new ByteArrayInputStream(samlResponseXml.getBytes(StandardCharsets.UTF_8)));

    String inResponseTo = doc.getDocumentElement().getAttribute("InResponseTo");
    if (expectedRequestId != null && !expectedRequestId.equals(inResponseTo)) {
      throw new SecurityException(
          "LogoutResponse InResponseTo non corrisponde. Atteso: "
              + expectedRequestId + ", trovato: " + inResponseTo);
    }

    NodeList statusNode = doc.getElementsByTagNameNS(SAMLP_NS, "StatusCode");
    if (statusNode.getLength() == 0) {
      throw new SecurityException("StatusCode mancante nella LogoutResponse");
    }

    String statusValue = statusNode.item(0).getAttributes()
        .getNamedItem("Value").getNodeValue();
    if (!statusValue.contains("Success")) {
      throw new SecurityException("Logout fallito. StatusCode: " + statusValue);
    }
  }
}
