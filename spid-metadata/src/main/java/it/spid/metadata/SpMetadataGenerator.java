package it.spid.metadata;

import java.security.cert.X509Certificate;
import java.util.Base64;

import it.spid.core.model.SpidConfig;
import it.spid.crypto.XmlSigner;

/**
 * Generatore di SP metadata XML per SPID.
 * Conforme alle specifiche AgID versione 1.2.
 */
public class SpMetadataGenerator {

  private final SpidConfig config;
  private X509Certificate certificate;
  private String organizationName;
  private String organizationUrl;
  private String contactEmail;
  private boolean isPublic = true;
  private XmlSigner signer;

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

  public SpMetadataGenerator withContactEmail(String email) {
    this.contactEmail = email;
    return this;
  }

  public SpMetadataGenerator asPublic(boolean isPublic) {
    this.isPublic = isPublic;
    return this;
  }

  /**
   * Imposta il signer per la firma digitale del metadata.
   * Se impostato, il metadata XML viene firmato prima di essere restituito.
   */
  public SpMetadataGenerator withSigner(XmlSigner signer) {
    this.signer = signer;
    return this;
  }

  public String build() throws Exception {
    if (certificate == null) {
      throw new IllegalStateException("Il certificato è obbligatorio per generare il metadata");
    }
    String certBase64 = Base64.getEncoder().encodeToString(certificate.getEncoded());

    String orgName = organizationName != null ? organizationName : "Service Provider";
    String orgUrl = organizationUrl != null ? organizationUrl : config.getEntityId();
    String email = contactEmail != null ? contactEmail : "info@" + extractDomain(orgUrl);

    // SingleLogoutService
    String sloBlock = "";
    if (config.getSingleLogoutServiceUrl() != null && !config.getSingleLogoutServiceUrl().isBlank()) {
      sloBlock = """
              <md:SingleLogoutService
                  Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                  Location="%s"/>
          """.formatted(config.getSingleLogoutServiceUrl());
    }

    // AttributeConsumingService — attributi minimi SPID obbligatori
    String attributeConsumingService = """
            <md:AttributeConsumingService index="0">
              <md:ServiceName xml:lang="it">%s</md:ServiceName>
              <md:RequestedAttribute Name="spidCode" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
              <md:RequestedAttribute Name="name" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
              <md:RequestedAttribute Name="familyName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
              <md:RequestedAttribute Name="fiscalNumber" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
              <md:RequestedAttribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
              <md:RequestedAttribute Name="dateOfBirth" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"/>
            </md:AttributeConsumingService>
        """
        .formatted(orgName);

    // ContactPerson con Company — obbligatorio per AgID
    String publicOrPrivate = isPublic ? "<spid:Public/>" : "<spid:Private/>";
    String contactPerson = """
            <md:ContactPerson contactType="other">
              <md:Extensions>
                %s
              </md:Extensions>
              <md:Company>%s</md:Company>
              <md:EmailAddress>%s</md:EmailAddress>
            </md:ContactPerson>
        """.formatted(publicOrPrivate, orgName, email);

    // ID univoco per il metadata — usato dalla firma
    String metadataId = "_spid-metadata-" + config.getEntityId().hashCode();

    String xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            xmlns:spid="https://spid.gov.it/saml-extensions"
            xmlns:xml="http://www.w3.org/XML/1998/namespace"
            ID="%s"
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
            <md:KeyDescriptor use="encryption">
              <ds:KeyInfo>
                <ds:X509Data>
                  <ds:X509Certificate>%s</ds:X509Certificate>
                </ds:X509Data>
              </ds:KeyInfo>
            </md:KeyDescriptor>
        %s    <md:AssertionConsumerService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                Location="%s"
                index="0"
                isDefault="true"/>
        %s  </md:SPSSODescriptor>
          <md:Organization>
            <md:OrganizationName xml:lang="it">%s</md:OrganizationName>
            <md:OrganizationDisplayName xml:lang="it">%s</md:OrganizationDisplayName>
            <md:OrganizationURL xml:lang="it">%s</md:OrganizationURL>
          </md:Organization>
        %s</md:EntityDescriptor>
        """.formatted(
        metadataId,
        config.getEntityId(),
        certBase64,
        certBase64,
        sloBlock,
        config.getAssertionConsumerServiceUrl(),
        attributeConsumingService,
        orgName,
        orgName,
        orgUrl,
        contactPerson);

    // Firma il metadata se è stato configurato un signer
    if (signer != null) {
      xml = signer.sign(xml, metadataId);
    }

    return xml;
  }

  private String extractDomain(String url) {
    try {
      return new java.net.URL(url).getHost();
    } catch (Exception e) {
      return "example.it";
    }
  }
}