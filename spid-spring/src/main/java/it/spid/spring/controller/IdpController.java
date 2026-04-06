package it.spid.spring.controller;

import it.spid.metadata.IdpInfo;
import it.spid.metadata.IdpRegistry;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Endpoint REST per la lista degli Identity Provider SPID.
 *
 * GET /spid/idps          → lista completa degli IdP
 * GET /spid/idps/{entityId} → dati di un singolo IdP
 * GET /spid/idps/search?q=aruba → ricerca per nome
 *
 * Usato tipicamente dal frontend per costruire il pulsante
 * "Scegli il tuo Identity Provider" con la lista ufficiale AgID.
 */
@RestController
@RequestMapping("/spid/idps")
public class IdpController {

    private final IdpRegistry idpRegistry;

    public IdpController(IdpRegistry idpRegistry) {
        this.idpRegistry = idpRegistry;
    }

    /**
     * Lista completa degli IdP SPID registrati su AgID.
     */
    @GetMapping
    public ResponseEntity<List<Map<String, String>>> listAll() {
        List<Map<String, String>> idps = idpRegistry.getAll().stream()
                .map(this::toMap)
                .toList();
        return ResponseEntity.ok(idps);
    }

    /**
     * Dati di un singolo IdP per entityId (URL-encoded).
     */
    @GetMapping("/by-entity-id")
    public ResponseEntity<?> getByEntityId(@RequestParam String entityId) {
        return idpRegistry.findByEntityId(entityId)
                .map(idp -> ResponseEntity.ok(toMap(idp)))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Ricerca IdP per nome (case-insensitive, parziale).
     * Es: GET /spid/idps/search?q=aruba
     */
    @GetMapping("/search")
    public ResponseEntity<List<Map<String, String>>> search(@RequestParam String q) {
        List<Map<String, String>> results = idpRegistry.searchByName(q).stream()
                .map(this::toMap)
                .toList();
        return ResponseEntity.ok(results);
    }

    /**
     * Forza il refresh della cache IdP.
     * Utile per ambienti di staging o dopo aggiornamenti AgID.
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh() {
        idpRegistry.refresh();
        return ResponseEntity.ok(Map.of(
                "count", idpRegistry.size(),
                "cacheValid", idpRegistry.isCacheValid()
        ));
    }

    private Map<String, String> toMap(IdpInfo idp) {
        var map = new java.util.LinkedHashMap<String, String>();
        map.put("entityId", idp.getEntityId());
        map.put("name", idp.getOrganizationName());
        map.put("ssoUrl", idp.getSsoUrl() != null ? idp.getSsoUrl() : "");
        map.put("sloUrl", idp.getSloUrl() != null ? idp.getSloUrl() : "");
        map.put("logoUrl", idp.getLogoUrl() != null ? idp.getLogoUrl() : "");
        return map;
    }
}