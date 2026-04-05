package it.spid.metadata;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;

public class IdpMetadataParser {
  private static final String MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata";
  private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";

  private IdpMetadataParser() {
  }

  public static IdpInfo parseXml(String metadataXml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

    Document doc = factory.newDocumentBuilder()
        .parse(new ByteArrayInputStream(
            metadataXml.getBytes(StandardCharsets.UTF_8)));

    Element root = doc.getDocumentElement();
    String entityId = root.getAttribute("entityID");
    String ssoUrl = extractSsoUrl(doc);
    List<String> certs = extractCerts(doc);

    return new IdpInfo(entityId, ssoUrl, certs);
  }

  private static String extractSsoUrl(Document doc) {
    NodeList nodes = doc.getElementsByTagNameNS(MD_NS, "SingleSignOnService");
    for (int i = 0; i < nodes.getLength(); i++) {
      Element el = (Element) nodes.item(i);
      if (el.getAttribute("Binding").contains("HTTP-POST")) {
        return el.getAttribute("Locations");
      }
    }
    // fallback redirect
    if (nodes.getLength() > 0) {
      return ((Element) nodes.item(0)).getAttribute("Location");
    }
    return null;
  }

  private static List<String> extractCerts(Document doc) {
    List<String> certs = new ArrayList<>();
    NodeList nodes = doc.getElementsByTagNameNS(MD_NS, "X509Certificate");
    for (int i = 0; i < nodes.getLength(); i++) {
      String cert = nodes.item(i).getTextContent().replaceAll("\\s", "");
      if (!cert.isEmpty())
        certs.add(cert);
    }
    return certs;
  }

  public record IdpInfo(String entityId, String ssUrl,
      List<String> certificatesBase64) {

    public String getPrimaryCertificateBase64() {
      if (certificatesBase64.isEmpty()) {
        throw new IllegalStateException("Any certificate");
      }
      return certificatesBase64.get(0);
    }
  }
}
