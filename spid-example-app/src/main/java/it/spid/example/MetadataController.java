package it.spid.example;

import it.spid.core.model.SpidConfig;
import it.spid.crypto.CertificateLoader;
import it.spid.metadata.SpMetadataGenerator;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;
import java.security.cert.X509Certificate;

@RestController
public class MetadataController {

  @GetMapping(value = "/spid/metadata", produces = MediaType.APPLICATION_XML_VALUE)
  public String metadata() throws Exception {
    SpidConfig config = SpidConfig.builder()
        .entityId("http://localhost:8080")
        .assertionConsumerServiceUrl("http://localhost:8080/spid/acs")
        .singleLogoutServiceUrl("http://localhost:8080/spid/logout")
        .build();

    InputStream certStream = new ClassPathResource("spid/cert.pem").getInputStream();
    X509Certificate cert = CertificateLoader.loadCertificate(certStream);

    return SpMetadataGenerator.create(config)
        .withCertificate(cert)
        .withOrganization("Test SP", "http://localhost:8080")
        .build();
  }
}