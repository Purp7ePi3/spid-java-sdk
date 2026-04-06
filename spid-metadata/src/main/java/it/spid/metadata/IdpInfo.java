package it.spid.metadata;

/**
 * Rappresenta un Identity Provider SPID registrato su AgID.
 */
public class IdpInfo {

  private final String entityId;
  private final String organizationName;
  private final String ssoUrl;
  private final String sloUrl;
  private final String certificateBase64;
  private final String logoUrl;

  public IdpInfo(String entityId, String organizationName,
      String ssoUrl, String sloUrl,
      String certificateBase64, String logoUrl) {
    this.entityId = entityId;
    this.organizationName = organizationName;
    this.ssoUrl = ssoUrl;
    this.sloUrl = sloUrl;
    this.certificateBase64 = certificateBase64;
    this.logoUrl = logoUrl;
  }

  public String getEntityId() {
    return entityId;
  }

  public String getOrganizationName() {
    return organizationName;
  }

  public String getSsoUrl() {
    return ssoUrl;
  }

  public String getSloUrl() {
    return sloUrl;
  }

  public String getCertificateBase64() {
    return certificateBase64;
  }

  public String getLogoUrl() {
    return logoUrl;
  }

  @Override
  public String toString() {
    return "IdpInfo{entityId='%s', name='%s'}".formatted(entityId, organizationName);
  }
}
