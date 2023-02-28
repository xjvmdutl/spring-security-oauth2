package com.example.oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class OAuth2ClientConfig {

  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    //WebSecurityConfigurerAdapter 를 상속받아 configure 를 오버라이드 해 구현했지만 더 이상 지원하지 않기 때문에 아래와 같이 구현하면 된다.
    return (web) -> web.ignoring().antMatchers("/static/js/**", "/static/images/**", "/static/css/**","/static/scss/**");
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(
        authRequest -> authRequest
            .antMatchers("/").permitAll() //root 만 접근 가능
            .anyRequest().authenticated());
    http
        .oauth2Client(Customizer.withDefaults());
    http.logout().logoutSuccessUrl("/");
    return http.build();
  }
}