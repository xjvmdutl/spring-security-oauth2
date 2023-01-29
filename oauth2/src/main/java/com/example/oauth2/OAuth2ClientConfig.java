package com.example.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

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

  /*
  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authRequest -> authRequest
        //.antMatchers("/loginPage").permitAll()
        .anyRequest().permitAll());
    //http.oauth2Login(oauth2 -> oauth2.loginPage("/loginPage"));//여기서 Customizer한 설정을 할 수 있다.
    http.oauth2Login(Customizer.withDefaults());
    return http.build();
  }

   */
  @Autowired
  private ClientRegistrationRepository clientRegistrationRepository;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    /*
    http.authorizeHttpRequests(authRequest -> authRequest.antMatchers("/home").permitAll()
        .anyRequest().authenticated());
    http.oauth2Login(Customizer.withDefaults());
    */
    /*
    http.logout()
        .logoutSuccessHandler(oidcLogoutSuccessHandler())
        .invalidateHttpSession(true)
        .clearAuthentication(true)
        .deleteCookies("JSESSIONID");
     */
    /*
    http.oauth2Login(oauth2 -> oauth2.loginPage("/login")
        .loginProcessingUrl("/login/oauth2/code/*") //둘다 사용할 수 있지만 우선순위가 redirectEndpoint 설정이 더 높기 떄문에 적용되지 않는다.
        .authorizationEndpoint(authorizationEndpointConfig ->
            //authorizationEndpointConfig.baseUri("/oauth2/authentication/**"))) //기본값
            authorizationEndpoi ntConfig.baseUri("/oauth2/v1/authorization"))
        .redirectionEndpoint(redirectionEndpointConfig ->
            //redirectionEndpointConfig.baseUri("/login/oauth2/code/*")) //기본값
            redirectionEndpointConfig.baseUri("/login/v1/oauth2/code/*"))
    );
     */
    /*
    http.oauth2Login(authLogin -> authLogin.authorizationEndpoint(
        authEndpoint -> authEndpoint.authorizationRequestResolver(
            customOAuth2AuthorizationRequestResolver())));
    http.logout().logoutSuccessUrl("/home");
     */
    http.authorizeHttpRequests(
            authRequest -> authRequest.antMatchers("/home2", "/client").permitAll().anyRequest().authenticated())
        //.oauth2Login(Customizer.withDefaults())
        .oauth2Client(Customizer.withDefaults()); //최종 사용자의 인증처리까지 해주지는 않는다.
    //클라이언트의 인증 처리까지만 가능하다. -> 이는 별도로 커스텀하게 작성해주어야 한다.
    http.logout().logoutSuccessUrl("/home2");
    return http.build();
  }

  private OAuth2AuthorizationRequestResolver customOAuth2AuthorizationRequestResolver() {
    return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
        "/oauth2/authorization");
  }

  private LogoutSuccessHandler oidcLogoutSuccessHandler() {
    OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(
        clientRegistrationRepository);
    successHandler.setPostLogoutRedirectUri("http://localhost:8081/login");
    return successHandler;
  }


}