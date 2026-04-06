package it.spid.core;

import java.math.BigInteger;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Helper per generare certificati X.509 self-signed nei test.
 * Non usare in produzione.
 */
public class TestCertificateHelper {
  private TestCertificateHelper() {
  }

  public static X509Certificate generateSelfSigned(KeyPair keyPair) throws Exception {
    X500Name subject = new X500Name("CN=Test SP, O=Test, C=IT");
    Instant now = Instant.now();

    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
        subject,
        BigInteger.valueOf(System.currentTimeMillis()),
        Date.from(now),
        Date.from(now.plus(365, ChronoUnit.DAYS)),
        subject,
        keyPair.getPublic());

    ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
        .setProvider("BC")
        .build(keyPair.getPrivate());

    return new JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(certBuilder.build(signer));
  }

}
