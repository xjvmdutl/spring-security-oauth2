package com.example.oauth2;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.spring5.processor.SpringUErrorsTagProcessor;

public class CustomOAuth2AuthorizationRequestResolver implements
    OAuth2AuthorizationRequestResolver {
  private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

  private ClientRegistrationRepository clientRegistrationRepository;
  private String baseUri;

  private DefaultOAuth2AuthorizationRequestResolver defaultOAuth2AuthorizationRequestResolver;

  private final AntPathRequestMatcher authorizationRequestMatcher;

  private static final Consumer<Builder> DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
      .withPkce();

  public CustomOAuth2AuthorizationRequestResolver(
      ClientRegistrationRepository clientRegistrationRepository, String BaseUri) {
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.authorizationRequestMatcher = new AntPathRequestMatcher(
        BaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
    this.baseUri = BaseUri;
    defaultOAuth2AuthorizationRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(
        clientRegistrationRepository, BaseUri);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
    String registrationId = resolveRegistrationId(request);
    if (registrationId == null) {
      return null;
    }
    if( registrationId.equals("keycloakWithPKCE")){
      OAuth2AuthorizationRequest oAuth2AuthorizationRequest = defaultOAuth2AuthorizationRequestResolver.resolve(
          request);
      return customResolver(oAuth2AuthorizationRequest, registrationId);
    }
    return defaultOAuth2AuthorizationRequestResolver.resolve(request);
  }

  @Override
  public OAuth2AuthorizationRequest resolve(HttpServletRequest request,
      String clientRegistrationId) {
    String registrationId = resolveRegistrationId(request);
    if (registrationId == null) {
      return null;
    }
    if( registrationId.equals("keycloakWithPKCE")){
      OAuth2AuthorizationRequest oAuth2AuthorizationRequest = defaultOAuth2AuthorizationRequestResolver.resolve(
          request);
      return customResolver(oAuth2AuthorizationRequest, clientRegistrationId);
    }
    return defaultOAuth2AuthorizationRequestResolver.resolve(request);
  }

  private OAuth2AuthorizationRequest customResolver(OAuth2AuthorizationRequest oAuth2AuthorizationRequest, String clientRegistrationId) {
    Map<String, Object> extraParam = new HashMap<>();
    extraParam.put("customName1", "customValue1");
    extraParam.put("customName2", "customValue2");
    extraParam.put("customName3", "customValue3");

    OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest
        .from(oAuth2AuthorizationRequest)
        .additionalParameters(extraParam);
    DEFAULT_PKCE_APPLIER.accept(builder);

    return builder.build();
  }

  private String resolveRegistrationId(HttpServletRequest request) {
    if (this.authorizationRequestMatcher.matches(request)) {
      return this.authorizationRequestMatcher.matcher(request).getVariables()
          .get(REGISTRATION_ID_URI_VARIABLE_NAME);
    }
    return null;
  }
}
