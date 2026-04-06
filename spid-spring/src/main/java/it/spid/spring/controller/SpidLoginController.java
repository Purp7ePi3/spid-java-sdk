package it.spid.spring.controller;

import it.spid.metadata.IdpInfo;
import it.spid.metadata.IdpRegistry;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

/**
 * Controller che gestisce il widget di selezione IdP.
 *
 * GET /spid/login-widget → serve la pagina HTML del widget
 * GET /spid/login-select → redirect verso IdP scelto (con cert)
 */
@Controller
@RequestMapping("/spid")
public class SpidLoginController {

  private final IdpRegistry idpRegistry;

  public SpidLoginController(IdpRegistry idpRegistry) {
    this.idpRegistry = idpRegistry;
  }

  /**
   * Serve la pagina HTML del widget — forward alla risorsa statica.
   */
  @GetMapping("/login-widget")
  public String loginWidget() {
    return "forward:/spid-login.html";
  }

  /**
   * Avvia il login verso l'IdP scelto nel widget.
   * Recupera automaticamente il certificato IdP dal registry.
   */
  @GetMapping("/login-select")
  public void loginSelect(@RequestParam("idpEntityId") String idpEntityId,
      @RequestParam(name = "level", defaultValue = "LEVEL_2") String level,
      HttpServletResponse response) throws Exception {

    IdpInfo idp = idpRegistry.findByEntityId(
        java.net.URLDecoder.decode(idpEntityId, "UTF-8"))
        .orElseThrow(() -> new IllegalArgumentException(
            "IdP non trovato: " + idpEntityId));

    if (idp.getSsoUrl() == null || idp.getSsoUrl().isBlank()) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST,
          "URL SSO non disponibile per questo IdP");
      return;
    }

    if (idp.getCertificateBase64() == null) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST,
          "Certificato IdP non disponibile");
      return;
    }

    StringBuilder loginUrl = new StringBuilder("/spid/login?")
        .append("idpEntityId=").append(java.net.URLEncoder.encode(idp.getEntityId(), "UTF-8"))
        .append("&idpSsoUrl=").append(java.net.URLEncoder.encode(idp.getSsoUrl(), "UTF-8"))
        .append("&idpCertB64=").append(java.net.URLEncoder.encode(idp.getCertificateBase64(), "UTF-8"))
        .append("&level=").append(level);

    if (idp.getSloUrl() != null && !idp.getSloUrl().isBlank()) {
      loginUrl.append("&idpSloUrl=")
          .append(java.net.URLEncoder.encode(idp.getSloUrl(), "UTF-8"));
    }

    response.sendRedirect(loginUrl.toString());
  }
}