# SPID Java SDK

SDK Java per integrare **SPID** (Sistema Pubblico di Identità Digitale) 
in applicazioni Spring Boot in pochi minuti.

## Cos'è

Integrare SPID da zero richiede settimane — protocolli SAML, certificati 
digitali, XML firmati, specifiche AgID. Con questa SDK lo fai in un pomeriggio.

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
| `GET /spid/logout` | Logout |
| `GET /spid/user` | Dati utente in JSON |

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
| `spid-core` | SAML 2.0, AuthnRequest, Response parsing |
| `spid-crypto` | Firma digitale XML, certificati |
| `spid-metadata` | Generazione SP metadata XML |
| `spid-validator` | Validazione risposta IdP |
| `spid-spring` | Autoconfiguration Spring Boot |
| `spid-example-app` | App demo funzionante |

## Test in locale

Puoi testare con l'ambiente demo SPID ufficiale:
[https://demo.spid.gov.it](https://demo.spid.gov.it)

## Licenza

Apache License 2.0

## Supporto

Stai usando questa SDK? Scrivici a **sdk@tuodominio.it** —  
offriamo supporto gratuito per i primi 10 progetti.