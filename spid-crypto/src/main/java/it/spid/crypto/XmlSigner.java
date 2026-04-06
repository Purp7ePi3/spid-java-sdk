package it.spid.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Firma digitale XML per SPID.
 * Implementa XMLDSig secondo le specifiche AgID:
 * - Algoritmo: RSA-SHA256
 * - Canonicalizzazione: C14N Exclusive
 * - Transform: Enveloped Signature
 */
public class XmlSigner {

  static {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private final PrivateKey privateKey;
  private final X509Certificate certificate;
  private final XMLSignatureFactory sigFactory;

  public XmlSigner(PrivateKey privateKey, X509Certificate certificate) {
    this.privateKey = privateKey;
    this.certificate = certificate;
    this.sigFactory = XMLSignatureFactory.getInstance("DOM");
  }

  /**
   * Firma un documento XML e restituisce l'XML firmato come stringa.
   *
   * @param xmlContent  XML da firmare
   * @param referenceId ID dell'elemento da firmare (es. l'ID della AuthnRequest)
   */
  public String sign(String xmlContent, String referenceId) throws Exception {
    Document doc = parseXml(xmlContent);
    signDocument(doc, referenceId);
    return documentToString(doc);
  }

  private void signDocument(Document doc, String referenceId) throws Exception {
    // Reference: punta all'elemento con l'ID della AuthnRequest
    Reference ref = sigFactory.newReference(
        "#" + referenceId,
        sigFactory.newDigestMethod(DigestMethod.SHA256, null),
        List.of(
            sigFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
            sigFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, (TransformParameterSpec) null)),
        null,
        null);

    // SignedInfo: algoritmo RSA-SHA256 come richiesto da AgID
    SignedInfo signedInfo = sigFactory.newSignedInfo(
        sigFactory.newCanonicalizationMethod(
            CanonicalizationMethod.EXCLUSIVE,
            (C14NMethodParameterSpec) null),
        sigFactory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
        Collections.singletonList(ref));

    // KeyInfo: include il certificato X.509
    KeyInfo keyInfo = buildKeyInfo();

    // Firma: inserita come primo figlio del root element
    XMLSignature signature = sigFactory.newXMLSignature(signedInfo, keyInfo);
    Element root = doc.getDocumentElement();
    root.setIdAttribute("ID", true);
    DOMSignContext signContext = new DOMSignContext(privateKey, root, root.getFirstChild());
    signature.sign(signContext);
  }

  private KeyInfo buildKeyInfo() throws Exception {
    KeyInfoFactory kif = sigFactory.getKeyInfoFactory();
    X509Data x509Data = kif.newX509Data(Collections.singletonList(certificate));
    return kif.newKeyInfo(Collections.singletonList(x509Data));
  }

  private Document parseXml(String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    return factory.newDocumentBuilder()
        .parse(new java.io.ByteArrayInputStream(xml.getBytes()));
  }

  private String documentToString(Document doc) throws Exception {
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer transformer = tf.newTransformer();
    StringWriter writer = new StringWriter();
    transformer.transform(new DOMSource(doc), new StreamResult(writer));
    return writer.toString();
  }
}
