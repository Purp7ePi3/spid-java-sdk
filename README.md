# SPID Java SDK

SDK Java per integrare **SPID** (Sistema Pubblico di Identità Digitale) 
in applicazioni Spring Boot in pochi minuti.

## Installazione

Aggiungi la dipendenza nel tuo `pom.xml`:
```xml
<dependency>
    <groupId>it.spid</groupId>
    <artifactId>spid-spring</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Configurazione

Nel tuo `application.yml`:
```yaml
spid:
  entity-id: https://tuaapp.it
  assertion-consumer-service-url: https://tuaapp.it/spid/acs
  single-logout-service-url: https://tuaapp.it/spid/logout
  minimum-level: LEVEL_2
  sign-requests: true
  certificate-path: classpath:spid/cert.pem
  private-key-path: classpath:spid/key.pem
```

## Utilizzo

Gli endpoint SPID sono disponibili automaticamente:

| Endpoint | Descrizione |
|----------|-------------|
| `GET /spid/login-widget` | Pagina selezione IdP con lista ufficiale AgID |
| `GET /spid/login-select` | Avvia login verso IdP scelto (con cert automatico) |
| `GET /spid/login` | Avvia login verso un IdP (parametri manuali) |
| `POST /spid/acs` | Riceve la risposta dall'IdP |
| `GET /spid/logout` | Avvia Single Logout verso l'IdP |
| `GET /spid/slo` | Riceve la LogoutResponse dall'IdP |
| `GET /spid/user` | Dati utente in JSON |
| `GET /spid/metadata` | Metadata SP firmato (conforme AgID) |
| `GET /spid/idps` | Lista IdP ufficiali AgID |
| `GET /spid/idps/search?q=aruba` | Cerca IdP per nome |
| `POST /spid/idps/refresh` | Forza refresh lista IdP |

Nel tuo controller:
```java
@Autowired
private SpidService spidService;

// Avvia login
SpidService.LoginRequest req = spidService.initiateLogin(
    idpEntityId, idpSsoUrl, SpidLevel.LEVEL_2
);
response.sendRedirect(req.redirectUrl());

// Dopo il login — dati utente
SpidUser user = spidService.processResponse(samlResponse, requestId);
user.getName();          // "Mario"
user.getFiscalNumber();  // "RSSMRA80A01H501U"
user.getEmail();         // "mario@esempio.it"
user.getSpidLevel();     // LEVEL_2

// Lista IdP
@Autowired
private IdpRegistry idpRegistry;

List<IdpInfo> idps = idpRegistry.getAll();
```

## Genera il tuo metadata SP

Ogni applicazione deve registrare il proprio metadata su AgID.

**1. Genera il certificato:**
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem \
  -out cert.pem -days 365 -nodes \
  -subj "/C=IT/ST=Italy/L=Roma/O=NomeAzienda/CN=tuaapp.it"
```

**2. Esponi il metadata:**
```java
@GetMapping(value = "/spid/metadata", produces = MediaType.APPLICATION_XML_VALUE)
public String metadata() throws Exception {
    SpidConfig config = SpidConfig.builder()
            .entityId("https://tuaapp.it")
            .assertionConsumerServiceUrl("https://tuaapp.it/spid/acs")
            .singleLogoutServiceUrl("https://tuaapp.it/spid/logout")
            .build();

    X509Certificate cert = CertificateLoader.loadCertificate(
        new ClassPathResource("spid/cert.pem").getInputStream()
    );

    return SpMetadataGenerator.create(config)
            .withCertificate(cert)
            .withOrganization("Nome Azienda", "https://tuaapp.it")
            .withContactEmail("info@tuaapp.it")
            .asPublic(true)
            .withSigner(xmlSigner)  // firma il metadata
            .build();
}
```

**3. Valida il metadata:**
```bash
pip install spid-sp-test
sudo apt install xmlsec1
spid_sp_test --metadata-url https://tuaapp.it/spid/metadata
```

**4. Registra il metadata su AgID:**  
Vai su [https://registry.spid.gov.it](https://registry.spid.gov.it) e registra 
l'URL del tuo metadata (es. `https://tuaapp.it/spid/metadata`).

## Struttura del progetto

| Modulo | Descrizione |
|--------|-------------|
| `spid-core` | SAML 2.0, AuthnRequest, Response parsing, Single Logout |
| `spid-crypto` | Firma digitale XML, certificati (PKCS#1 e PKCS#8) |
| `spid-metadata` | Generazione SP metadata XML conforme AgID, lista IdP |
| `spid-validator` | Validazione risposta IdP, firma obbligatoria, replay attack prevention |
| `spid-spring` | Autoconfiguration Spring Boot, controller REST, widget IdP |
| `spid-example-app` | App demo funzionante |

## Test in locale

Valida il metadata con lo strumento ufficiale AgID:
```bash
~/.local/bin/spid_sp_test --metadata-url http://localhost:8080/spid/metadata
```

Per testare il flusso completo serve un dominio con HTTPS — vedi la sezione **Per andare in produzione**.

## Per andare in produzione

1. **Dominio reale** — es. `tuaapp.it`
2. **HTTPS** — certificato SSL (Let's Encrypt è gratuito)
3. **Certificato SPID-compliant** — emesso da una CA accreditata AgID
4. **Registrazione su AgID** — submit metadata su `registry.spid.gov.it`

---

## ✅ Fatto

- [x] SAML 2.0 AuthnRequest e Response parsing
- [x] Firma digitale XML (PKCS#1 e PKCS#8)
- [x] Generazione SP metadata conforme AgID (AttributeConsumingService, ContactPerson, firma)
- [x] Validazione metadata con spid-sp-test (87/87 test passano)
- [x] Validazione SAMLResponse completa (firma, audience, scadenza, InResponseTo)
- [x] Firma AuthnRequest con RSA-SHA256 (`sign-requests: true`)
- [x] Validazione firma IdP obbligatoria sulla SAMLResponse
- [x] Replay attack prevention (`RequestIdStore`)
- [x] Single Logout SAML 2.0 (`LogoutRequest` + `LogoutResponse`)
- [x] Spring Boot Autoconfiguration (`AutoConfiguration.imports`)
- [x] Lista IdP ufficiali AgID con cache 24h e auto-refresh
- [x] Widget selezione IdP con dark mode, ricerca e design moderno
- [x] Endpoint REST IdP (`/spid/idps`, `/spid/idps/search`, `/spid/idps/refresh`)
- [x] Test unitari per tutti i moduli

---

## 📋 TODO

- [ ] **Sessioni distribuite** — supporto Redis per deployment in cluster
- [ ] **Spring Boot Actuator** — endpoint `/actuator/spid` per monitoring e stato cache IdP
- [ ] **Pubblicazione Maven Central** — release pubblica con versioning semantico
- [ ] **GitHub Actions CI/CD** — pipeline con test automatici su ogni PR

---

## Licenza

Apache License 2.0