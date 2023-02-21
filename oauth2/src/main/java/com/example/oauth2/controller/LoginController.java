package com.example.oauth2.controller;

import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
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

    OAuth2AuthorizationSuccessHandler successHandler = (authorizedClient, principal, attributes) -> {
      oAuth2AuthorizedClientRepository
          .saveAuthorizedClient(authorizedClient, principal,
              (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
              (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
      System.out.println("authorizedClient = " + authorizedClient);
      System.out.println("principal = " + principal);
      System.out.println("attributes = " + attributes);
    };
    oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler);


    OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(
        auth2AuthorizeRequest);

    model.addAttribute("authorizedClient", authorizedClient.getAccessToken().getTokenValue());
    //client 자체가 사용자 역할을 겸해서 하기 때문에 별도의 사용자 정보를 통해 인증처리하는 과정이 필요가 없다
    //해당 방식은 토큰은 발급 받았지만 실제 유저에 대한 인증은 받지 않은 것이기 때문에 해당 방식을 사용할 때는 클라이언트 끼리 통신할 때 많이 사용한다

    return "home";
  }

  @GetMapping("/logout")
  public String logout(Authentication authentication, HttpServletRequest request,
      HttpServletResponse response) {
    SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    logoutHandler.logout(request, response, authentication);
    return "redirect:/";
  }
}
