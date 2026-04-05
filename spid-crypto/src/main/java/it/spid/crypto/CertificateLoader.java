package it.spid.crypto;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Carica certificati X.509 e chiavi private da file PEM.
 *
 * Formato atteso:
 * - Certificato: -----BEGIN CERTIFICATE-----
 * - Chiave privata: -----BEGIN RSA PRIVATE KEY----- o -----BEGIN PRIVATE
 * KEY-----
 */
public class CertificateLoader {

  private CertificateLoader() {
  }

  /**
   * Carica un certificato X.509 da file PEM.
   */
  public static X509Certificate loadCertificate(Path pemPath) throws Exception {
    try (InputStream is = Files.newInputStream(pemPath)) {
      return loadCertificate(is);
    }
  }

  /**
   * Carica un certificato X.509 da InputStream (es. classpath resource).
   */
  public static X509Certificate loadCertificate(InputStream pemStream) throws Exception {
    try (PEMParser parser = new PEMParser(new InputStreamReader(pemStream))) {
      Object obj = parser.readObject();

      if (obj instanceof X509CertificateHolder holder) {
        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(holder);
      }
      throw new IllegalArgumentException(
          "Il file non contiene un certificato X.509 valido. Trovato: " +
              (obj != null ? obj.getClass().getSimpleName() : "null"));
    }
  }

  /**
   * Carica una chiave privata RSA da file PEM.
   */
  public static PrivateKey loadPrivateKey(Path pemPath) throws Exception {
    try (InputStream is = Files.newInputStream(pemPath)) {
      return loadPrivateKey(is);
    }
  }

  /**
   * Carica una chiave privata RSA da InputStream.
   */
  public static PrivateKey loadPrivateKey(InputStream pemStream) throws Exception {
    try (PEMParser parser = new PEMParser(new InputStreamReader(pemStream))) {
      Object obj = parser.readObject();

      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      if (obj instanceof PEMKeyPair keyPair) {
        return converter.getKeyPair(keyPair).getPrivate();
      }

      if (obj instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
        throw new IllegalArgumentException(
            "La chiave privata è protetta da password. " +
                "Usa loadEncryptedPrivateKey() con la password.");
      }

      throw new IllegalArgumentException(
          "Il file non contiene una chiave privata valida. Trovato: " +
              (obj != null ? obj.getClass().getSimpleName() : "null"));
    }
  }

  /**
   * Carica un certificato X.509 da stringa Base64 (senza header PEM).
   * Utile per certificati estratti dai metadata IdP.
   */
  public static X509Certificate loadCertificateFromBase64(String base64Cert) throws Exception {
    byte[] decoded = java.util.Base64.getDecoder().decode(
        base64Cert.replaceAll("\\s", ""));
    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
    return (X509Certificate) cf.generateCertificate(
        new java.io.ByteArrayInputStream(decoded));
  }
}
