package io.security.oauth2.springsecurityoauth2;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;


@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http)
      throws Exception { //빈이기 때문에 HttpSecurity를 주입 받을 수 있다
    http.authorizeHttpRequests().anyRequest().authenticated();
    http.httpBasic().authenticationEntryPoint(new CustomAuthenticationEntryPoint());
    /*
    http.formLogin();
    http.httpBasic();
    http.exceptionHandling().authenticationEntryPoint(new AuthenticationEntryPoint() {
      @Override
      public void commence(HttpServletRequest request, HttpServletResponse response,
          AuthenticationException authException) throws IOException, ServletException {
        System.out.println("Custom EntryPoint"); //커스텀한 EntryPoint 설정
      }
    });
     */
    //http.apply(new CustomSecurityConfigurer().setFlag(false)); //빌더 패턴과 비슷하게 사용할 수 있다.
    //http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    return http.build();
  }

  /*
  @Bean
  public SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
    //httpSecurity를 각각 생성해야 하므로 httpConfiguration에서 빈이 다르게 생성이 되어야한다
    http.authorizeHttpRequests().anyRequest().authenticated();
    http.httpBasic();
    return http.build();
  }
   */
}
