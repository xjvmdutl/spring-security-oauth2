package com.example.oauth2;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  //@Autowired
  //private ClientRegistrationRepository clientRegistrationRepository; //사용자의 엔드포인트를 알수 있다

  @GetMapping("/")
  public String index() {
    /*
    ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(
        "keycloak");
    String clientId = clientRegistration.getClientId();
    System.out.println("clientId = " + clientId);

    String redirectUri = clientRegistration.getRedirectUri();
    System.out.println("redirectUri = " + redirectUri);
     */
    return "index";
  }
  /*
  @GetMapping("/user")
  public OAuth2User user(String accessToken) {
    ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(
        "keycloak");
    OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken,
        Instant.now(), Instant.MAX);

    OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, oAuth2AccessToken);
    DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
    OAuth2User oAuth2User = defaultOAuth2UserService.loadUser(oAuth2UserRequest);

    return oAuth2User;
  }

  @GetMapping("/oidc")
  public OAuth2User oidc(String accessToken, String idToken) {
    ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(
        "keycloak");
    OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(TokenType.BEARER, accessToken,
        Instant.now(), Instant.MAX);

    Map<String, Object> idTokenClaims = new HashMap<>();
    idTokenClaims.put(IdTokenClaimNames.ISS, "http://localhost:8080/realms/oauth2");
    idTokenClaims.put(IdTokenClaimNames.SUB, "OIDC0");
    idTokenClaims.put("preferred_username", "user");
    OidcIdToken oidcIdToken = new OidcIdToken(idToken, Instant.now(), Instant.MAX, idTokenClaims);

    OidcUserRequest oidcUserRequest = new OidcUserRequest(clientRegistration, oAuth2AccessToken, oidcIdToken);
    OidcUserService oidcUserService = new OidcUserService();
    OAuth2User oAuth2User = oidcUserService.loadUser(oidcUserRequest);

    return oAuth2User;
  }
   */

  @GetMapping("/user")
  public OAuth2User user(Authentication authentication) {
    //파라미터를 통해 받아오는 경우
    //OAuth2AuthenticationToken authentication1 = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
    OAuth2AuthenticationToken authentication2 = (OAuth2AuthenticationToken) authentication;
    OAuth2User oAuth2User = authentication2.getPrincipal();
    return oAuth2User;
  }

  @GetMapping("/oauth2User")
  public OAuth2User oAuth2User(@AuthenticationPrincipal OAuth2User oAuth2User) {
    System.out.println("oAuth2User = " + oAuth2User);
    return oAuth2User;
  }

  @GetMapping("/oidcUser")
  public OidcUser oidcUser(@AuthenticationPrincipal OidcUser oidcUser) {
    //기본적으로 OidcUser 같은 경우에도 OAuth2User를 상속받기 떄문에 OAuth2User 로 받을 수 있지만 명확하게 oidc를 받는다는것을 명시하기 위해 사용하는것이다.
    System.out.println("oidcUser = " + oidcUser);
    return oidcUser;
  }
}
