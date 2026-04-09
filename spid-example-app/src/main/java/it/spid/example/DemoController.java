package it.spid.example;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import it.spid.core.model.SpidUser;
import jakarta.servlet.http.HttpSession;

@Controller
public class DemoController {
  @GetMapping("/")
  public String index() {
    return "index";
  }

  @GetMapping("/dashboard")
  public String dashboard(HttpSession session, Model model) {
    SpidUser user = (SpidUser) session.getAttribute("spid_user");

    if (user == null) {
      return "redirect:/";
    }

    model.addAttribute("user", user);
    return "dashboard";
  }

  @GetMapping("/spid/login-page")
  public String loginPage(Model model) {
    return "redirect:/spid/login-widget";
  }
}
