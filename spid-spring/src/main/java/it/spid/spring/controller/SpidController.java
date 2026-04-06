package it.spid.spring.controller;

import it.spid.core.model.SpidLevel;
import it.spid.core.model.SpidUser;
import it.spid.core.saml.SpidService;
import it.spid.validator.RequestIdStore;
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
 *
 * Endpoint:
 * GET /spid/login → redirect verso IdP (AuthnRequest)
 * POST /spid/acs → callback IdP (ACS)
 * GET /spid/logout → avvia Single Logout verso IdP
 * GET /spid/slo → riceve LogoutResponse dall'IdP
 * GET /spid/user → dati utente corrente (JSON)
 */
@RestController
@RequestMapping("/spid")
public class SpidController {

  private static final Logger log = LoggerFactory.getLogger(SpidController.class);

  private static final String SESSION_REQUEST_ID = "spid_request_id";
  private static final String SESSION_LOGOUT_ID = "spid_logout_request_id";
  private static final String SESSION_USER = "spid_user";
  private static final String SESSION_IDP_CERT = "spid_idp_cert";
  private static final String SESSION_IDP_SLO_URL = "spid_idp_slo_url";

  private final SpidService spidService;
  private final SamlResponseValidator validator;
  private final RequestIdStore requestIdStore;

  public SpidController(SpidService spidService, SamlResponseValidator validator,
      RequestIdStore requestIdStore) {
    this.spidService = spidService;
    this.validator = validator;
    this.requestIdStore = requestIdStore;
  }

  /**
   * Avvia il login SPID verso un Identity Provider.
   *
   * @param idpSloUrl URL Single Logout dell'IdP (opzionale, per abilitare SLO)
   */
  @GetMapping("/login")
  public void login(@RequestParam("idpEntityId") String idpEntityId,
      @RequestParam("idpSsoUrl") String idpSsoUrl,
      @RequestParam("idpCertB64") String idpCertB64,
      @RequestParam(name = "idpSloUrl", required = false) String idpSloUrl,
      @RequestParam(name = "level", defaultValue = "LEVEL_2") SpidLevel level,
      HttpSession session,
      HttpServletResponse response) throws Exception {

    SpidService.LoginRequest loginReq = spidService.initiateLogin(idpEntityId, idpSsoUrl, level);

    requestIdStore.register(loginReq.requestId());
    session.setAttribute(SESSION_REQUEST_ID, loginReq.requestId());
    session.setAttribute(SESSION_IDP_CERT, idpCertB64);
    if (idpSloUrl != null) {
      session.setAttribute(SESSION_IDP_SLO_URL, idpSloUrl);
    }

    log.info("Avviato login SPID verso IdP: {} (requestId: {})", idpEntityId, loginReq.requestId());
    response.sendRedirect(loginReq.redirectUrl());
  }

  /**
   * Assertion Consumer Service (ACS) - riceve la risposta dall'IdP.
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

    try {
      requestIdStore.consumeOrThrow(requestId);
    } catch (SecurityException e) {
      log.error("Replay attack rilevato per requestId: {}", requestId);
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Richiesta non valida");
      return;
    }

    String samlXml = it.spid.core.saml.SamlEncoder.decodeBase64(samlResponseB64);
    SamlResponseValidator.ValidationResult result = validator.validate(samlXml, requestId, idpCert);

    if (!result.isValid()) {
      log.error("SAMLResponse non valida: {}", result.getErrors());
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Autenticazione SPID fallita");
      return;
    }

    SpidUser user = spidService.processResponse(samlResponseB64, requestId);
    session.setAttribute(SESSION_USER, user);
    session.removeAttribute(SESSION_REQUEST_ID);

    log.info("Login SPID completato per: {} (CF: {})", user.getFullName(), user.getFiscalNumber());
    response.sendRedirect("/dashboard");
  }

  /**
   * Avvia il Single Logout SPID.
   * Se l'IdP supporta SLO, redirige verso di lui con una LogoutRequest.
   * Altrimenti esegue solo il logout locale.
   */
  @GetMapping("/logout")
  public void logout(HttpSession session, HttpServletResponse response) throws Exception {
    SpidUser user = (SpidUser) session.getAttribute(SESSION_USER);
    String idpSloUrl = (String) session.getAttribute(SESSION_IDP_SLO_URL);

    if (user == null) {
      session.invalidate();
      response.sendRedirect("/");
      return;
    }

    log.info("Avviato logout SPID per: {}", user.getFiscalNumber());

    if (idpSloUrl != null && user.getNameId() != null) {
      SpidService.LogoutRequest logoutReq = spidService.initiateSingleLogout(idpSloUrl, user);
      session.setAttribute(SESSION_LOGOUT_ID, logoutReq.requestId());
      log.info("Redirect verso IdP per SLO (requestId: {})", logoutReq.requestId());
      response.sendRedirect(logoutReq.redirectUrl());
    } else {
      // Fallback: logout solo locale (nameId non disponibile o IdP senza SLO)
      log.info("SLO non disponibile — logout solo locale per: {}", user.getFiscalNumber());
      session.invalidate();
      response.sendRedirect("/");
    }
  }

  /**
   * Single Logout Service (SLO) — riceve la LogoutResponse dall'IdP.
   * L'IdP redirige qui dopo aver completato il logout sul suo lato.
   */
  @GetMapping("/slo")
  public void slo(@RequestParam(value = "SAMLResponse", required = false) String samlResponseB64,
      @RequestParam(value = "RelayState", required = false) String relayState,
      HttpSession session,
      HttpServletResponse response) throws Exception {

    String logoutRequestId = (String) session.getAttribute(SESSION_LOGOUT_ID);

    if (samlResponseB64 != null) {
      try {
        spidService.processSingleLogoutResponse(samlResponseB64, logoutRequestId);
        log.info("Single Logout completato con successo (requestId: {})", logoutRequestId);
      } catch (Exception e) {
        // Procediamo comunque col logout locale per non bloccare l'utente
        log.warn("Errore nella LogoutResponse IdP: {} — procedo con logout locale", e.getMessage());
      }
    }

    session.invalidate();
    response.sendRedirect("/");
  }

  /**
   * Dati utente SPID corrente come JSON.
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
        "idpEntityId", user.getIdpEntityId()));
  }
}