package com.example.oauth2.controller;

import java.time.Clock;
import java.time.Duration;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
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

  private Duration clockSkew = Duration.ofSeconds(3600);

  private Clock clock = Clock.systemUTC();

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
        auth2AuthorizeRequest);//authorizedClient에 토큰이 있지만 바로 만료되어 있다

//    권한부여 타입을 변경하지 않고 실행
//    if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())
//        && authorizedClient.getRefreshToken() != null) {
//      //authorizedClient 존재하고, AccessToken이 만료 되어 있고, RefreshToken이 만료되지 않았을 경우
//      oAuth2AuthorizedClientManager.authorize(auth2AuthorizeRequest);
//    }

    //권한부여 타입을 변경하고 실행
    if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())
        && authorizedClient.getRefreshToken() != null) {

      //아래 클래스에 대한 재정의가 필요하므로 재생성 한것이다.
      ClientRegistration clientRegistration = ClientRegistration.withClientRegistration(
              authorizedClient.getClientRegistration())
          .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
          .build();
      OAuth2AuthorizedClient oAuth2AuthorizedClient = new OAuth2AuthorizedClient(
          clientRegistration,
          authorizedClient.getPrincipalName(),
          authorizedClient.getAccessToken(),
          authorizedClient.getRefreshToken()
      );
      OAuth2AuthorizeRequest auth2AuthorizeRequest2 =
          OAuth2AuthorizeRequest
              .withAuthorizedClient(oAuth2AuthorizedClient)
              .principal(authentication)
              .attribute(HttpServletRequest.class.getName(), request)
              .attribute(HttpServletResponse.class.getName(), response)
              .build();
      oAuth2AuthorizedClientManager.authorize(auth2AuthorizeRequest2);
    }

    model.addAttribute("AccessToken", authorizedClient.getAccessToken().getTokenValue());
    model.addAttribute("RefreshToken", authorizedClient.getRefreshToken().getTokenValue());

    return "home";
  }

  private boolean hasTokenExpired(OAuth2Token token) {
    return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
  }

  @GetMapping("/logout")
  public String logout(Authentication authentication, HttpServletRequest request,
      HttpServletResponse response) {
    SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
    logoutHandler.logout(request, response, authentication);
    return "redirect:/";
  }
}
