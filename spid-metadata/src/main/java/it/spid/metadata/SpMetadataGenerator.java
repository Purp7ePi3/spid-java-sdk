package it.spid.metadata;

import java.security.cert.X509Certificate;
import java.util.Base64;

import it.spid.core.model.SpidConfig;

public class SpMetadataGenerator {

  private final SpidConfig config;
  private X509Certificate certificate;
  private String organizationName;
  private String organizationUrl;

  private SpMetadataGenerator(SpidConfig config) {
    this.config = config;
  }

  public static SpMetadataGenerator create(SpidConfig config) {
    return new SpMetadataGenerator(config);
  }

  public SpMetadataGenerator withCertificate(X509Certificate certificate) {
    this.certificate = certificate;
    return this;
  }

  public SpMetadataGenerator withOrganization(String name, String url) {
    this.organizationName = name;
    this.organizationUrl = url;
    return this;
  }

  public String build() throws Exception {
    if (certificate == null) {
      throw new IllegalAccessError("Need certificate");
    }
    String certBase64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
    return """
        <?xml version="1.0" encoding="UTF-8"?>
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            entityID="%s">
          <md:SPSSODescriptor
              AuthnRequestsSigned="true"
              WantAssertionsSigned="true"
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:KeyDescriptor use="signing">
              <ds:KeyInfo>
                <ds:X509Data>
                  <ds:X509Certificate>%s</ds:X509Certificate>
                </ds:X509Data>
              </ds:KeyInfo>
            </md:KeyDescriptor>
            <md:AssertionConsumerService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                Location="%s"
                index="0"/>
          </md:SPSSODescriptor>
        </md:EntityDescriptor>
        """.formatted(
        config.getEntityId(),
        certBase64,
        config.getAssertionConsumerServiceUrl());

  }

}
