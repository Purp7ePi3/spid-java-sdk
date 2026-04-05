package it.spid.example;

import java.time.Instant;
import java.util.Map;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import it.spid.core.model.SpidLevel;
import it.spid.core.model.SpidUser;
import jakarta.servlet.http.HttpSession;

@Controller
public class MockIdpController {

  @GetMapping("/mock/login")
  public String loginForm() {
    return "mock-login";
  }

  // Process form and build mock user
  @PostMapping("/mock/auth")
  public String auth(@RequestParam("name") String name,
      @RequestParam("surname") String surname,
      @RequestParam("taxId") String taxId,
      @RequestParam("email") String email,
      HttpSession session) {

    SpidUser user = SpidUser.builder()
        .name(name)
        .familyName(surname)
        .fiscalNumber(taxId)
        .email(email)
        .spidLevel(SpidLevel.LEVEL_2)
        .idpEntityId("https://demo.spid.gov.it")
        .authenticationTime(Instant.now())
        .attributes(Map.of(
            "name", name,
            "familyName", surname,
            "fiscalNumber", taxId,
            "email", email))
        .build();
    session.setAttribute("spid_user", user);
    return "redirect:/dashboard";
  }
}
