package com.example.oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

/*
@Configuration
public class OAuth2ClientConfig {

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    return new InMemoryClientRegistrationRepository(keycloakClientRegistration());
  }

  private ClientRegistration keycloakClientRegistration() {
    //ClientRegistration 을 만드는 유틸성 클래스
    return ClientRegistrations
        .fromIssuerLocation("http://localhost:8080/realms/oauth2")
        .registrationId("keycloak")
        .clientId("oauth2-client-app")
        .clientSecret("xSlqD456gfAeLZO93BLbTwQys0NEc8KL")
        .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
        .build();
  }
}
 */
@EnableWebSecurity
public class OAuth2ClientConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authRequest -> authRequest
        //.antMatchers("/loginPage").permitAll()
        .anyRequest().permitAll());
    //http.oauth2Login(oauth2 -> oauth2.loginPage("/loginPage"));//여기서 Customizer한 설정을 할 수 있다.
    http.oauth2Login(Customizer.withDefaults());
    return http.build();
  }
}