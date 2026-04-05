package it.spid.core.saml;

import it.spid.core.model.SpidLevel;
import it.spid.core.model.SpidUser;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Parsing della SAMLResponse ricevuta dall'Identity Provider SPID.
 * Estrae gli attributi utente e valida la struttura base della risposta.
 *
 * NOTA: per produzione usare sempre SamlValidator prima del parsing.
 */
public class SamlResponseParser {

    // Namespace SAML
    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";

    private SamlResponseParser() {}

    /**
     * Parsa la SAMLResponse (già decodificata da Base64) e restituisce lo SpidUser.
     *
     * @param samlResponseXml XML della risposta IdP
     * @param expectedRequestId ID della AuthnRequest originale (per validare InResponseTo)
     */
    public static SpidUser parse(String samlResponseXml, String expectedRequestId) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        // Protezione XXE
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        Document doc = factory.newDocumentBuilder()
                .parse(new ByteArrayInputStream(samlResponseXml.getBytes(StandardCharsets.UTF_8)));

        // Valida InResponseTo
        String inResponseTo = doc.getDocumentElement().getAttribute("InResponseTo");
        if (!expectedRequestId.equals(inResponseTo)) {
            throw new SecurityException("InResponseTo non corrisponde alla request: " + inResponseTo);
        }

        // Valida StatusCode
        NodeList statusNodes = doc.getElementsByTagNameNS(SAMLP_NS, "StatusCode");
        if (statusNodes.getLength() > 0) {
            String statusValue = statusNodes.item(0).getAttributes()
                    .getNamedItem("Value").getNodeValue();
            if (!statusValue.contains("Success")) {
                throw new SecurityException("Autenticazione fallita. StatusCode: " + statusValue);
            }
        }

        // Estrai attributi
        Map<String, String> attributes = extractAttributes(doc);

        // Estrai livello SPID
        SpidLevel level = extractSpidLevel(doc);

        // Estrai metadati sessione
        String sessionIndex = extractSessionIndex(doc);
        String nameId = extractNameId(doc);
        String idpEntityId = extractIdpEntityId(doc);

        return SpidUser.builder()
                .fiscalNumber(attributes.get("fiscalNumber"))
                .name(attributes.get("name"))
                .familyName(attributes.get("familyName"))
                .email(attributes.get("email"))
                .dateOfBirth(attributes.get("dateOfBirth"))
                .placeOfBirth(attributes.get("placeOfBirth"))
                .sessionIndex(sessionIndex)
                .nameId(nameId)
                .spidLevel(level)
                .idpEntityId(idpEntityId)
                .authenticationTime(Instant.now())
                .attributes(attributes)
                .build();
    }

    private static Map<String, String> extractAttributes(Document doc) {
        Map<String, String> attrs = new HashMap<>();
        NodeList attrNodes = doc.getElementsByTagNameNS(SAML_NS, "Attribute");

        for (int i = 0; i < attrNodes.getLength(); i++) {
            org.w3c.dom.Element attr = (org.w3c.dom.Element) attrNodes.item(i);
            String name = attr.getAttribute("Name");
            NodeList values = attr.getElementsByTagNameNS(SAML_NS, "AttributeValue");
            if (values.getLength() > 0) {
                // Rimuovi prefisso "spid-code:" se presente
                String cleanName = name.contains(":") ? name.substring(name.lastIndexOf(":") + 1) : name;
                attrs.put(cleanName, values.item(0).getTextContent().trim());
            }
        }
        return attrs;
    }

    private static SpidLevel extractSpidLevel(Document doc) {
        NodeList nodes = doc.getElementsByTagNameNS(SAML_NS, "AuthnContextClassRef");
        if (nodes.getLength() > 0) {
            String uri = nodes.item(0).getTextContent().trim();
            return SpidLevel.fromUri(uri);
        }
        return SpidLevel.LEVEL_1;
    }

    private static String extractSessionIndex(Document doc) {
        NodeList nodes = doc.getElementsByTagNameNS(SAML_NS, "AuthnStatement");
        if (nodes.getLength() > 0) {
            return ((org.w3c.dom.Element) nodes.item(0)).getAttribute("SessionIndex");
        }
        return null;
    }

    private static String extractNameId(Document doc) {
        NodeList nodes = doc.getElementsByTagNameNS(SAML_NS, "NameID");
        return nodes.getLength() > 0 ? nodes.item(0).getTextContent().trim() : null;
    }

    private static String extractIdpEntityId(Document doc) {
        NodeList nodes = doc.getElementsByTagNameNS(SAML_NS, "Issuer");
        return nodes.getLength() > 0 ? nodes.item(0).getTextContent().trim() : null;
    }
}
