package it.spid.core.model;

/**
 * Configurazione del Service Provider (SP) per SPID.
 * Contiene tutti i parametri necessari per identificarsi verso gli Identity Provider.
 */
public class SpidConfig {

    private String entityId;
    private String assertionConsumerServiceUrl;
    private String singleLogoutServiceUrl;
    private String privateKeyPath;
    private String certificatePath;
    private SpidLevel minimumSpidLevel;
    private boolean signRequests;

    private SpidConfig() {}

    public static Builder builder() {
        return new Builder();
    }

    public String getEntityId() { return entityId; }
    public String getAssertionConsumerServiceUrl() { return assertionConsumerServiceUrl; }
    public String getSingleLogoutServiceUrl() { return singleLogoutServiceUrl; }
    public String getPrivateKeyPath() { return privateKeyPath; }
    public String getCertificatePath() { return certificatePath; }
    public SpidLevel getMinimumSpidLevel() { return minimumSpidLevel; }
    public boolean isSignRequests() { return signRequests; }

    public static class Builder {
        private final SpidConfig config = new SpidConfig();

        public Builder entityId(String entityId) {
            config.entityId = entityId;
            return this;
        }

        public Builder assertionConsumerServiceUrl(String url) {
            config.assertionConsumerServiceUrl = url;
            return this;
        }

        public Builder singleLogoutServiceUrl(String url) {
            config.singleLogoutServiceUrl = url;
            return this;
        }

        public Builder privateKeyPath(String path) {
            config.privateKeyPath = path;
            return this;
        }

        public Builder certificatePath(String path) {
            config.certificatePath = path;
            return this;
        }

        public Builder minimumSpidLevel(SpidLevel level) {
            config.minimumSpidLevel = level;
            return this;
        }

        public Builder signRequests(boolean sign) {
            config.signRequests = sign;
            return this;
        }

        public SpidConfig build() {
            validate();
            return config;
        }

        private void validate() {
            if (config.entityId == null || config.entityId.isBlank()) {
                throw new IllegalStateException("entityId è obbligatorio");
            }
            if (config.assertionConsumerServiceUrl == null) {
                throw new IllegalStateException("assertionConsumerServiceUrl è obbligatorio");
            }
            if (config.minimumSpidLevel == null) {
                config.minimumSpidLevel = SpidLevel.LEVEL_1;
            }
        }
    }
}
