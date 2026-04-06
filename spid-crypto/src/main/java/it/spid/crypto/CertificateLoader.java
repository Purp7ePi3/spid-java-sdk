package it.spid.crypto;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Carica certificati X.509 e chiavi private da file PEM.
 *
 * Supporta:
 * - Certificato: -----BEGIN CERTIFICATE-----
 * - Chiave PKCS#1: -----BEGIN RSA PRIVATE KEY-----
 * - Chiave PKCS#8: -----BEGIN PRIVATE KEY----- (generata da openssl pkcs8 o
 * keytool)
 */
public class CertificateLoader {

  private CertificateLoader() {
  }

  public static X509Certificate loadCertificate(Path pemPath) throws Exception {
    try (InputStream is = Files.newInputStream(pemPath)) {
      return loadCertificate(is);
    }
  }

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

  public static PrivateKey loadPrivateKey(Path pemPath) throws Exception {
    try (InputStream is = Files.newInputStream(pemPath)) {
      return loadPrivateKey(is);
    }
  }

  public static PrivateKey loadPrivateKey(InputStream pemStream) throws Exception {
    try (PEMParser parser = new PEMParser(new InputStreamReader(pemStream))) {
      Object obj = parser.readObject();
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

      // PKCS#1 — -----BEGIN RSA PRIVATE KEY-----
      if (obj instanceof PEMKeyPair keyPair) {
        return converter.getKeyPair(keyPair).getPrivate();
      }

      // PKCS#8 — -----BEGIN PRIVATE KEY-----
      if (obj instanceof PrivateKeyInfo keyInfo) {
        return converter.getPrivateKey(keyInfo);
      }

      if (obj instanceof org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo) {
        throw new IllegalArgumentException(
            "La chiave privata è protetta da password. " +
                "Genera una chiave senza password con: openssl pkcs8 -nocrypt ...");
      }

      throw new IllegalArgumentException(
          "Il file non contiene una chiave privata valida. Trovato: " +
              (obj != null ? obj.getClass().getSimpleName() : "null"));
    }
  }

  public static X509Certificate loadCertificateFromBase64(String base64Cert) throws Exception {
    byte[] decoded = java.util.Base64.getDecoder().decode(
        base64Cert.replaceAll("\\s", ""));
    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
    return (X509Certificate) cf.generateCertificate(
        new java.io.ByteArrayInputStream(decoded));
  }
}