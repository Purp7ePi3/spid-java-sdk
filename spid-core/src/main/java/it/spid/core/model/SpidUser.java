package it.spid.core.model;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

/**
 * Rappresenta un utente autenticato tramite SPID.
 * Contiene gli attributi restituiti dall'Identity Provider.
 */
public class SpidUser {

  // Attributi minimi SPID
  private String taxId; // codice fiscale
  private String name; // nome
  private String familyName; // cognome
  private String email;
  private String dateOfBirth;
  private String placeOfBirth;

  // Metadati sessione
  private String sessionIndex;
  private String nameId;
  private SpidLevel spidLevel;
  private String idpEntityId;
  private Instant authenticationTime;

  // Tutti gli attributi raw dall'IdP
  private Map<String, String> attributes;

  private SpidUser() {
  }

  public String getFiscalNumber() {
    return taxId;
  }

  public String getName() {
    return name;
  }

  public String getFamilyName() {
    return familyName;
  }

  public String getEmail() {
    return email;
  }

  public String getDateOfBirth() {
    return dateOfBirth;
  }

  public String getPlaceOfBirth() {
    return placeOfBirth;
  }

  public String getSessionIndex() {
    return sessionIndex;
  }

  public String getNameId() {
    return nameId;
  }

  public SpidLevel getSpidLevel() {
    return spidLevel;
  }

  public String getIdpEntityId() {
    return idpEntityId;
  }

  public Instant getAuthenticationTime() {
    return authenticationTime;
  }

  public Map<String, String> getAttributes() {
    return Collections.unmodifiableMap(attributes);
  }

  public String getFullName() {
    return name + " " + familyName;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private final SpidUser user = new SpidUser();

    public Builder fiscalNumber(String v) {
      user.taxId = v;
      return this;
    }

    public Builder name(String v) {
      user.name = v;
      return this;
    }

    public Builder familyName(String v) {
      user.familyName = v;
      return this;
    }

    public Builder email(String v) {
      user.email = v;
      return this;
    }

    public Builder dateOfBirth(String v) {
      user.dateOfBirth = v;
      return this;
    }

    public Builder placeOfBirth(String v) {
      user.placeOfBirth = v;
      return this;
    }

    public Builder sessionIndex(String v) {
      user.sessionIndex = v;
      return this;
    }

    public Builder nameId(String v) {
      user.nameId = v;
      return this;
    }

    public Builder spidLevel(SpidLevel v) {
      user.spidLevel = v;
      return this;
    }

    public Builder idpEntityId(String v) {
      user.idpEntityId = v;
      return this;
    }

    public Builder authenticationTime(Instant v) {
      user.authenticationTime = v;
      return this;
    }

    public Builder attributes(Map<String, String> v) {
      user.attributes = v;
      return this;
    }

    public SpidUser build() {
      return user;
    }
  }
}
