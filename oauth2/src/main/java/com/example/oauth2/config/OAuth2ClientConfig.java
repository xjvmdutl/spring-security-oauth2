package com.example.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;


@EnableWebSecurity
public class OAuth2ClientConfig {

  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
            authRequest -> authRequest.antMatchers("/", "/oauth2Login", "/logout", "/client")
                .permitAll()
                .anyRequest().authenticated())
        .oauth2Client(Customizer.withDefaults());
    return http.build();
  }
}