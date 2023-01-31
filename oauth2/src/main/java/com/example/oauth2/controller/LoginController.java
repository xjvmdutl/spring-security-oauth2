package com.example.oauth2.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class LoginController {

  /*
  @GetMapping("/loginPage")
  public String loginPage() {
    return "loginPage";
  }
   */
  /*
  @GetMapping("/login")
  public String login(){
    return "login";
  }
   */
  @GetMapping("/oauth2Login")
  public String oauth2Login(Model model, HttpServletRequest request, HttpServletResponse response) {
    return "redirect:/";
  }

  @GetMapping("/logout")
  public String logout(Authentication authentication, HttpServletRequest request,
      HttpServletResponse response) {
    SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    logoutHandler.logout(request, response, authentication);
    return "redirect:/";
  }
}
