package com.example.oauth2.config;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import javax.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;

@Configuration
public class AppConfig {

  @Bean
  public DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager(
      ClientRegistrationRepository clientRegistrationRepository,
      OAuth2AuthorizedClientRepository clientRepository) {

    OAuth2AuthorizedClientProvider auth2AuthorizedClientProvider =
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .clientCredentials()
            .password()
            .refreshToken()
            .build();

    DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager =
        new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, clientRepository);

    oAuth2AuthorizedClientManager.setAuthorizedClientProvider(auth2AuthorizedClientProvider);
    oAuth2AuthorizedClientManager.setContextAttributesMapper(contextAttributesMapper());
    return oAuth2AuthorizedClientManager;
  }

  private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper() {
    return oAuth2AuthorizeRequest -> {
      Map<String, Object> contextAttributes = new HashMap<>();
      HttpServletRequest request = oAuth2AuthorizeRequest.getAttribute(HttpServletRequest.class.getName());
      String username = request.getParameter(OAuth2ParameterNames.USERNAME);
      String password = request.getParameter(OAuth2ParameterNames.PASSWORD);
      if(StringUtils.hasText(username) && StringUtils.hasText(password)){
        contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
        contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
      }
      return contextAttributes;
    };
  }
}
