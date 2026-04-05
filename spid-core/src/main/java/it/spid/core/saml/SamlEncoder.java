package it.spid.core.saml;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

/**
 * Utilità per encoding/decoding SAML secondo specifiche.
 * SAML usa: Deflate → Base64 → URL encoding per HTTP-Redirect binding.
 */
public class SamlEncoder {

    private SamlEncoder() {}

    /**
     * Comprime (Deflate) e codifica (Base64) una stringa XML SAML.
     * Usato per HTTP-Redirect binding.
     */
    public static String deflateAndEncode(String xml) throws Exception {
        byte[] input = xml.getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        try (DeflaterOutputStream deflaterStream = new DeflaterOutputStream(output, deflater)) {
            deflaterStream.write(input);
        }

        return Base64.getEncoder().encodeToString(output.toByteArray());
    }

    /**
     * Decodifica (Base64) e decomprime (Inflate) una risposta SAML.
     */
    public static String decodeAndInflate(String encoded) throws Exception {
        byte[] compressed = Base64.getDecoder().decode(encoded);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Inflater inflater = new Inflater(true);
        try (InflaterOutputStream inflaterStream = new InflaterOutputStream(output, inflater)) {
            inflaterStream.write(compressed);
        }

        return output.toString(StandardCharsets.UTF_8);
    }

    /**
     * Decodifica solo Base64 (per POST binding, non compresso).
     */
    public static String decodeBase64(String encoded) {
        byte[] decoded = Base64.getDecoder().decode(encoded);
        return new String(decoded, StandardCharsets.UTF_8);
    }
}
