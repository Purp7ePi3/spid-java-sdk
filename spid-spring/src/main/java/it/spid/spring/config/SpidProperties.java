package it.spid.spring.config;

import it.spid.core.model.SpidLevel;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Proprietà di configurazione SPID per Spring Boot.
 *
 * In application.yml:
 *
 * spid:
 *   entity-id: https://miaapp.it
 *   assertion-consumer-service-url: https://miaapp.it/spid/acs
 *   single-logout-service-url: https://miaapp.it/spid/logout
 *   minimum-level: LEVEL_2
 *   certificate-path: classpath:spid/cert.pem
 *   private-key-path: classpath:spid/key.pem
 *   sign-requests: true
 */
@ConfigurationProperties(prefix = "spid")
public class SpidProperties {

    private String entityId;
    private String assertionConsumerServiceUrl;
    private String singleLogoutServiceUrl;
    private SpidLevel minimumLevel = SpidLevel.LEVEL_2;
    private String certificatePath;
    private String privateKeyPath;
    private boolean signRequests = true;

    // Getter e setter
    public String getEntityId() { return entityId; }
    public void setEntityId(String entityId) { this.entityId = entityId; }

    public String getAssertionConsumerServiceUrl() { return assertionConsumerServiceUrl; }
    public void setAssertionConsumerServiceUrl(String url) { this.assertionConsumerServiceUrl = url; }

    public String getSingleLogoutServiceUrl() { return singleLogoutServiceUrl; }
    public void setSingleLogoutServiceUrl(String url) { this.singleLogoutServiceUrl = url; }

    public SpidLevel getMinimumLevel() { return minimumLevel; }
    public void setMinimumLevel(SpidLevel level) { this.minimumLevel = level; }

    public String getCertificatePath() { return certificatePath; }
    public void setCertificatePath(String path) { this.certificatePath = path; }

    public String getPrivateKeyPath() { return privateKeyPath; }
    public void setPrivateKeyPath(String path) { this.privateKeyPath = path; }

    public boolean isSignRequests() { return signRequests; }
    public void setSignRequests(boolean signRequests) { this.signRequests = signRequests; }
}
