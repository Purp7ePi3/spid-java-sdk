package it.spid.spring.controller;

import it.spid.core.model.SpidLevel;
import it.spid.core.model.SpidUser;
import it.spid.core.saml.SpidService;
import it.spid.validator.SamlResponseValidator;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controller Spring Boot per il flusso SPID completo.
 * Espone gli endpoint standard SPID:
 *
 *   GET  /spid/login?idpEntityId=...&level=LEVEL_2   → redirect verso IdP
 *   POST /spid/acs                                    → callback IdP (ACS)
 *   GET  /spid/logout                                 → avvia logout
 *   GET  /spid/user                                   → dati utente corrente (API)
 *
 * Puoi estendere questa classe o disabilitarla con @ConditionalOnProperty
 * e scrivere il tuo controller personalizzato.
 */
@RestController
@RequestMapping("/spid")
public class SpidController {

    private static final Logger log = LoggerFactory.getLogger(SpidController.class);
    private static final String SESSION_REQUEST_ID = "spid_request_id";
    private static final String SESSION_USER = "spid_user";
    private static final String SESSION_IDP_CERT = "spid_idp_cert";

    private final SpidService spidService;
    private final SamlResponseValidator validator;

    public SpidController(SpidService spidService, SamlResponseValidator validator) {
        this.spidService = spidService;
        this.validator = validator;
    }

    /**
     * Avvia il login SPID verso un Identity Provider.
     *
     * @param idpEntityId  EntityID dell'IdP scelto dall'utente (es. pulsante "Entra con SPID")
     * @param idpSsoUrl    URL SSO dell'IdP (recuperato dal suo metadata)
     * @param idpCertB64   Certificato IdP in Base64 (per validare la risposta)
     * @param level        Livello SPID richiesto (default: LEVEL_2)
     */
    @GetMapping("/login")
    public void login(@RequestParam String idpEntityId,
                      @RequestParam String idpSsoUrl,
                      @RequestParam String idpCertB64,
                      @RequestParam(defaultValue = "LEVEL_2") SpidLevel level,
                      HttpSession session,
                      HttpServletResponse response) throws Exception {

        SpidService.LoginRequest loginReq = spidService.initiateLogin(idpEntityId, idpSsoUrl, level);

        // Salva in sessione per la validazione al ritorno
        session.setAttribute(SESSION_REQUEST_ID, loginReq.requestId());
        session.setAttribute(SESSION_IDP_CERT, idpCertB64);

        log.info("Avviato login SPID verso IdP: {} (requestId: {})", idpEntityId, loginReq.requestId());
        response.sendRedirect(loginReq.redirectUrl());
    }

    /**
     * Assertion Consumer Service (ACS) - riceve la risposta dall'IdP.
     * L'IdP fa un POST a questo endpoint con la SAMLResponse.
     */
    @PostMapping("/acs")
    public void acs(@RequestParam("SAMLResponse") String samlResponseB64,
                    @RequestParam(value = "RelayState", required = false) String relayState,
                    HttpSession session,
                    HttpServletResponse response) throws Exception {

        String requestId = (String) session.getAttribute(SESSION_REQUEST_ID);
        String idpCert = (String) session.getAttribute(SESSION_IDP_CERT);

        if (requestId == null) {
            log.warn("ACS ricevuto senza requestId in sessione — possibile CSRF");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Sessione non valida");
            return;
        }

        // Decodifica e valida prima di fare qualsiasi cosa
        String samlXml = it.spid.core.saml.SamlEncoder.decodeBase64(samlResponseB64);
        SamlResponseValidator.ValidationResult result = validator.validate(samlXml, requestId, idpCert);

        if (!result.isValid()) {
            log.error("SAMLResponse non valida: {}", result.getErrors());
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Autenticazione SPID fallita");
            return;
        }

        // Parsing utente
        SpidUser user = spidService.processResponse(samlResponseB64, requestId);
        session.setAttribute(SESSION_USER, user);
        session.removeAttribute(SESSION_REQUEST_ID);

        log.info("Login SPID completato per: {} (CF: {})", user.getFullName(), user.getFiscalNumber());
        response.sendRedirect("/dashboard");
    }

    /**
     * Restituisce i dati dell'utente SPID corrente come JSON.
     * Utile per frontend SPA.
     */
    @GetMapping("/user")
    public ResponseEntity<?> currentUser(HttpSession session) {
        SpidUser user = (SpidUser) session.getAttribute(SESSION_USER);

        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Non autenticato"));
        }

        return ResponseEntity.ok(Map.of(
                "name", user.getName(),
                "familyName", user.getFamilyName(),
                "fiscalNumber", user.getFiscalNumber(),
                "email", user.getEmail() != null ? user.getEmail() : "",
                "spidLevel", user.getSpidLevel().name(),
                "idpEntityId", user.getIdpEntityId()
        ));
    }

    /**
     * Logout dalla sessione locale.
     * (Single Logout SAML da implementare nel prossimo step)
     */
    @GetMapping("/logout")
    public void logout(HttpSession session, HttpServletResponse response) throws Exception {
        SpidUser user = (SpidUser) session.getAttribute(SESSION_USER);
        if (user != null) {
            log.info("Logout SPID per: {}", user.getFiscalNumber());
        }
        session.invalidate();
        response.sendRedirect("/");
    }
}
