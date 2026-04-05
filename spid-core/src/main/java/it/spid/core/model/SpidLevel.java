package it.spid.core.model;

/**
 * Livelli di autenticazione SPID definiti da AgID.
 * LEVEL_1 = username/password
 * LEVEL_2 = OTP o app (il più usato)
 * LEVEL_3 = certificato digitale fisico
 */
public enum SpidLevel {

    LEVEL_1("https://www.spid.gov.it/SpidL1", 1),
    LEVEL_2("https://www.spid.gov.it/SpidL2", 2),
    LEVEL_3("https://www.spid.gov.it/SpidL3", 3);

    private final String uri;
    private final int value;

    SpidLevel(String uri, int value) {
        this.uri = uri;
        this.value = value;
    }

    public String getUri() { return uri; }
    public int getValue() { return value; }

    public static SpidLevel fromUri(String uri) {
        for (SpidLevel level : values()) {
            if (level.uri.equals(uri)) return level;
        }
        throw new IllegalArgumentException("SpidLevel non riconosciuto: " + uri);
    }
}
