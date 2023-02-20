package com.example.oauth2.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

  @Autowired
  private DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

  @Autowired
  private OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

  @GetMapping("/oauth2Login")
  public String oauth2Login(Model model, HttpServletRequest request, HttpServletResponse response) {

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    OAuth2AuthorizeRequest auth2AuthorizeRequest =
        OAuth2AuthorizeRequest.withClientRegistrationId("keycloak")
            .principal(authentication)
            .attribute(HttpServletRequest.class.getName(), request)
            .attribute(HttpServletResponse.class.getName(), response)
            .build();

    OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(
        auth2AuthorizeRequest);
    if (authorizedClient != null) {

    }
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
