package it.spid.crypto;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Verifica la firma digitale XML nella SAMLResponse ricevuta dall'IdP.
 *
 * SPID richiede di validare la firma di ogni risposta IdP prima di
 * estrarre qualsiasi dato utente.
 */
public class XmlSignatureValidator {

    private XmlSignatureValidator() {}

    /**
     * Verifica la firma XML usando la chiave pubblica del certificato IdP.
     *
     * @param signedXml      XML della risposta IdP (già decodificata da Base64)
     * @param idpCertificate Certificato X.509 dell'IdP (dal suo metadata)
     * @return true se la firma è valida
     * @throws SecurityException se la firma non è presente o non è valida
     */
    public static boolean validate(String signedXml, X509Certificate idpCertificate) throws Exception {
        return validate(signedXml, idpCertificate.getPublicKey());
    }

    /**
     * Verifica la firma XML usando direttamente la chiave pubblica IdP.
     */
    public static boolean validate(String signedXml, PublicKey idpPublicKey) throws Exception {
        Document doc = parseXml(signedXml);

        // Cerca il nodo Signature nell'XML
        NodeList signatureNodes = doc.getElementsByTagNameNS(
                XMLSignature.XMLNS, "Signature"
        );

        if (signatureNodes.getLength() == 0) {
            throw new SecurityException("Nessuna firma trovata nella SAMLResponse. " +
                    "Le risposte SPID devono essere firmate dall'IdP.");
        }

        // Valida ogni firma presente (di solito una sola)
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

        for (int i = 0; i < signatureNodes.getLength(); i++) {
            DOMValidateContext validateContext = new DOMValidateContext(
                    idpPublicKey,
                    signatureNodes.item(i)
            );

            XMLSignature signature = factory.unmarshalXMLSignature(validateContext);
            boolean valid = signature.validate(validateContext);

            if (!valid) {
                // Log dettaglio per debug
                boolean coreValid = signature.getSignatureValue().validate(validateContext);
                boolean refsValid = signature.getSignedInfo().getReferences().stream()
                        .allMatch(ref -> {
                            try {
                                return ((javax.xml.crypto.dsig.Reference) ref).validate(validateContext);
                            } catch (Exception e) {
                                return false;
                            }
                        });

                throw new SecurityException(String.format(
                        "Firma XML non valida. SignatureValue: %s, References: %s",
                        coreValid, refsValid
                ));
            }
        }

        return true;
    }

    private static Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return factory.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }
}
