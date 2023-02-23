package com.example.oauth2.filter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
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
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

public class CustomOAuth2AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

  private static final String DEFAULT_FILTER_PROCESSING_URI = "/oauth2Login/**";

  private DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
  private OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;

  private OAuth2AuthorizationSuccessHandler successHandler;

  private Duration clockSkew = Duration.ofSeconds(3600);

  private Clock clock = Clock.systemUTC();

  public CustomOAuth2AuthenticationFilter(
      DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager,
      OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
    super(DEFAULT_FILTER_PROCESSING_URI); //Filter가 동작하기 위해 매칭될 URL 정보를 전달해준다.

    this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;
    this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;
    this.successHandler = (authorizedClient, principal, attributes) -> { //최종 인가를 받고 난 후, 해당 핸들러 실행
      //아직 해당 상태에서는 principal은 비인증 상태이다.
      oAuth2AuthorizedClientRepository
          .saveAuthorizedClient(authorizedClient, principal,
              (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
              (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
      System.out.println("authorizedClient = " + authorizedClient);
      System.out.println("principal = " + principal);
      System.out.println("attributes = " + attributes);
    };
    oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null) { //익명사용자용 토큰을 만들어 주면 된다
      authentication = new AnonymousAuthenticationToken("anonymous", "anonymousUser",
          AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    }

    OAuth2AuthorizeRequest authorizeRequest =
        OAuth2AuthorizeRequest.withClientRegistrationId("keycloak")
            .principal(authentication)
            .attribute(HttpServletRequest.class.getName(), request)
            .attribute(HttpServletResponse.class.getName(), response)
            .build();

    OAuth2AuthorizedClient authorizedClient =
        oAuth2AuthorizedClientManager.authorize(authorizeRequest);
    if (authorizedClient != null && hasTokenExpired(authorizedClient.getAccessToken())
        && authorizedClient.getRefreshToken() != null) {
      authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);
    }
    if (authorizedClient != null) {
      OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
      ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
      OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
      OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, accessToken);
      OAuth2User oAuth2User = oAuth2UserService.loadUser(oAuth2UserRequest);

      SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
      authorityMapper.setPrefix("SYSTEM_");
      Set<GrantedAuthority> grantedAuthorities = authorityMapper.mapAuthorities(
          oAuth2User.getAuthorities());

      OAuth2AuthenticationToken oAuth2AuthenticationToken = new OAuth2AuthenticationToken(
          oAuth2User, grantedAuthorities, clientRegistration.getRegistrationId());

      SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
      this.successHandler.onAuthorizationSuccess(authorizedClient, oAuth2AuthenticationToken,
          createAttributes(request, response));
      return oAuth2AuthenticationToken;
    }

    return null;
  }

  private boolean hasTokenExpired(OAuth2Token token) {
    return this.clock.instant().isAfter(token.getExpiresAt().minus(this.clockSkew));
  }

  private static Map<String, Object> createAttributes(HttpServletRequest servletRequest,
      HttpServletResponse servletResponse) {
    Map<String, Object> attributes = new HashMap<>();
    attributes.put(HttpServletRequest.class.getName(), servletRequest);
    attributes.put(HttpServletResponse.class.getName(), servletResponse);
    return attributes;
  }
}
