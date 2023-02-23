package com.example.oauth2.config;

import com.example.oauth2.filter.CustomOAuth2AuthenticationFilter;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration(proxyBeanMethods = false)
public class OAuth2ClientConfig {

  @Autowired
  private DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager;

  @Autowired
  private OAuth2AuthorizedClientRepository authorizedClientRepository;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
        authRequest -> authRequest.antMatchers("/", "/oauth2Login", "/client").permitAll()
            .anyRequest().authenticated());
    http
        .oauth2Client(Customizer.withDefaults());
    http
        .addFilterBefore(customOAuth2AuthenticationFilter(),
            UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }

  private CustomOAuth2AuthenticationFilter customOAuth2AuthenticationFilter() {
    CustomOAuth2AuthenticationFilter auth2AuthenticationFilter = new CustomOAuth2AuthenticationFilter(
        auth2AuthorizedClientManager, authorizedClientRepository);
    auth2AuthenticationFilter.setAuthenticationSuccessHandler(
        (request, response, authentication) -> response.sendRedirect("/home"));
    return auth2AuthenticationFilter;
  }
}