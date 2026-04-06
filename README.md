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
  certificate-path: classpath:spid/cert.pem
  private-key-path: classpath:spid/key.pem
```

## Utilizzo

Gli endpoint SPID sono disponibili automaticamente:

| Endpoint | Descrizione |
|----------|-------------|
| `GET /spid/login` | Avvia il login verso un IdP |
| `POST /spid/acs` | Riceve la risposta dall'IdP |
| `GET /spid/logout` | Avvia Single Logout verso l'IdP |
| `GET /spid/slo` | Riceve la LogoutResponse dall'IdP |
| `GET /spid/user` | Dati utente in JSON |
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
            .build();

    X509Certificate cert = CertificateLoader.loadCertificate(
        new ClassPathResource("spid/cert.pem").getInputStream()
    );

    return SpMetadataGenerator.create(config)
            .withCertificate(cert)
            .withOrganization("Nome Azienda", "https://tuaapp.it")
            .build();
}
```

**3. Registra il metadata su AgID:**  
Vai su [https://registry.spid.gov.it](https://registry.spid.gov.it) e registra 
l'URL del tuo metadata (es. `https://tuaapp.it/spid/metadata`).

## Struttura del progetto

| Modulo | Descrizione |
|--------|-------------|
| `spid-core` | SAML 2.0, AuthnRequest, Response parsing, Single Logout |
| `spid-crypto` | Firma digitale XML, certificati (PKCS#1 e PKCS#8) |
| `spid-metadata` | Generazione SP metadata XML, lista IdP AgID |
| `spid-validator` | Validazione risposta IdP, replay attack prevention |
| `spid-spring` | Autoconfiguration Spring Boot, controller REST |
| `spid-example-app` | App demo funzionante |

## Test in locale

Puoi testare con l'ambiente demo SPID ufficiale:
[https://demo.spid.gov.it](https://demo.spid.gov.it)

---

## ✅ Fatto

- [x] SAML 2.0 AuthnRequest e Response parsing
- [x] Firma digitale XML (PKCS#1 e PKCS#8)
- [x] Generazione SP metadata (con SLO e KeyDescriptor encryption)
- [x] Validazione SAMLResponse completa (firma, audience, scadenza, InResponseTo)
- [x] Replay attack prevention (`RequestIdStore`)
- [x] Single Logout SAML 2.0 (`LogoutRequest` + `LogoutResponse`)
- [x] Spring Boot Autoconfiguration (`AutoConfiguration.imports`)
- [x] Lista IdP ufficiali AgID con cache 24h e auto-refresh
- [x] Endpoint REST IdP (`/spid/idps`, `/spid/idps/search`, `/spid/idps/refresh`)
- [x] Test unitari per tutti i moduli

---

## 📋 TODO

- [ ] **Firma AuthnRequest** — abilitare e testare `sign-requests: true` con firma RSA-SHA256
- [ ] **Validazione firma IdP** — verificare la firma XML della SAMLResponse con il certificato IdP reale
- [ ] **Widget selezione IdP** — pagina HTML/JS con loghi ufficiali SPID e bottone "Entra con SPID"
- [ ] **Supporto multi-IdP dinamico** — switch IdP senza restart dell'app
- [ ] **Sessioni distribuite** — supporto Redis per deployment in cluster
- [ ] **Spring Boot Actuator** — endpoint `/actuator/spid` per monitoring e stato della cache IdP
- [ ] **Pubblicazione Maven Central** — release pubblica con versioning semantico
- [ ] **GitHub Actions CI/CD** — pipeline con test automatici su ogni PR

---

## Licenza

Apache License 2.0