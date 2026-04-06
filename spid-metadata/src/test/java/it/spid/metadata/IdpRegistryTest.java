package it.spid.metadata;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test per IdpRegistry.
 * Usa XML sintetico per testare il parsing senza chiamate HTTP.
 */
public class IdpRegistryTest {

  // XML federation minimale con 2 IdP fittizi
  private static final String FEDERATION_XML = """
      <?xml version="1.0" encoding="UTF-8"?>
      <md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                             xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <md:EntityDescriptor entityID="https://loginspid.aruba.it">
          <md:IDPSSODescriptor
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:KeyDescriptor use="signing">
              <ds:KeyInfo><ds:X509Data>
                <ds:X509Certificate>CERTARUBABASE64==</ds:X509Certificate>
              </ds:X509Data></ds:KeyInfo>
            </md:KeyDescriptor>
            <md:SingleSignOnService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                Location="https://loginspid.aruba.it/ServiceActiveComponent"/>
            <md:SingleLogoutService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                Location="https://loginspid.aruba.it/SingleLogoutService"/>
          </md:IDPSSODescriptor>
          <md:Organization>
            <md:OrganizationName xml:lang="it">Aruba ID</md:OrganizationName>
            <md:OrganizationDisplayName xml:lang="it">Aruba ID</md:OrganizationDisplayName>
            <md:OrganizationURL xml:lang="it">https://www.aruba.it</md:OrganizationURL>
          </md:Organization>
        </md:EntityDescriptor>
        <md:EntityDescriptor entityID="https://posteid.poste.it">
          <md:IDPSSODescriptor
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:SingleSignOnService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                Location="https://posteid.poste.it/sso"/>
          </md:IDPSSODescriptor>
          <md:Organization>
            <md:OrganizationDisplayName xml:lang="it">Poste ID</md:OrganizationDisplayName>
            <md:OrganizationURL xml:lang="it">https://www.poste.it</md:OrganizationURL>
          </md:Organization>
        </md:EntityDescriptor>
      </md:EntitiesDescriptor>
      """;

  private List<IdpInfo> parseXml(String xml) throws Exception {
    IdpRegistry registry = new IdpRegistry();
    Method method = IdpRegistry.class.getDeclaredMethod("parseFederation", String.class);
    method.setAccessible(true);
    @SuppressWarnings("unchecked")
    List<IdpInfo> result = (List<IdpInfo>) method.invoke(registry, xml);
    return result;
  }

  @Test
  void parseFederation_trovaDueIdp() throws Exception {
    List<IdpInfo> idps = parseXml(FEDERATION_XML);
    assertEquals(2, idps.size());
  }

  @Test
  void parseFederation_entityIdCorretto() throws Exception {
    List<IdpInfo> idps = parseXml(FEDERATION_XML);
    assertTrue(idps.stream().anyMatch(i -> i.getEntityId().equals("https://loginspid.aruba.it")));
    assertTrue(idps.stream().anyMatch(i -> i.getEntityId().equals("https://posteid.poste.it")));
  }

  @Test
  void parseFederation_nomeOrganizzazione() throws Exception {
    List<IdpInfo> idps = parseXml(FEDERATION_XML);
    Optional<IdpInfo> aruba = idps.stream()
        .filter(i -> i.getEntityId().equals("https://loginspid.aruba.it"))
        .findFirst();
    assertTrue(aruba.isPresent());
    assertEquals("Aruba ID", aruba.get().getOrganizationName());
  }

  @Test
  void parseFederation_ssoUrlPostPreferenzaPostRedirect() throws Exception {
    List<IdpInfo> idps = parseXml(FEDERATION_XML);
    // Aruba ha HTTP-POST → deve restituire quello
    IdpInfo aruba = idps.stream()
        .filter(i -> i.getEntityId().equals("https://loginspid.aruba.it"))
        .findFirst().orElseThrow();
    assertEquals("https://loginspid.aruba.it/ServiceActiveComponent", aruba.getSsoUrl());

    // Poste ha solo HTTP-Redirect → fallback
    IdpInfo poste = idps.stream()
        .filter(i -> i.getEntityId().equals("https://posteid.poste.it"))
        .findFirst().orElseThrow();
    assertEquals("https://posteid.poste.it/sso", poste.getSsoUrl());
  }

  @Test
  void parseFederation_sloUrl() throws Exception {
    List<IdpInfo> idps = parseXml(FEDERATION_XML);
    IdpInfo aruba = idps.stream()
        .filter(i -> i.getEntityId().equals("https://loginspid.aruba.it"))
        .findFirst().orElseThrow();
    assertEquals("https://loginspid.aruba.it/SingleLogoutService", aruba.getSloUrl());
  }

  @Test
  void parseFederation_certificato() throws Exception {
    List<IdpInfo> idps = parseXml(FEDERATION_XML);
    IdpInfo aruba = idps.stream()
        .filter(i -> i.getEntityId().equals("https://loginspid.aruba.it"))
        .findFirst().orElseThrow();
    assertEquals("CERTARUBABASE64==", aruba.getCertificateBase64());
  }

  @Test
  void isCacheValid_inizialmenteFalso() {
    IdpRegistry registry = new IdpRegistry();
    assertFalse(registry.isCacheValid());
  }

  @Test
  void size_inizialmenteZero() {
    IdpRegistry registry = new IdpRegistry();
    assertEquals(0, registry.size());
  }
}