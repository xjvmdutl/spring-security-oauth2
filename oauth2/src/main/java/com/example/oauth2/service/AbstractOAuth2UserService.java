package com.example.oauth2.service;

import com.example.oauth2.model.GoogleUser;
import com.example.oauth2.model.KeycloakUser;
import com.example.oauth2.model.NaverUser;
import com.example.oauth2.model.ProviderUser;
import com.example.oauth2.model.User;
import com.example.oauth2.repository.UserRepository;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Getter
public abstract class AbstractOAuth2UserService {

  @Autowired
  private UserService userService;

  @Autowired
  private UserRepository userRepository;
  
  protected ProviderUser providerUser(ClientRegistration clientRegistration,
      OAuth2User oAuth2User) {
    //registrationId 로 구분
    String registrationId = clientRegistration.getRegistrationId();
    if (registrationId.equals("keycloak")) {
      return new KeycloakUser(oAuth2User, clientRegistration);
    } else if (registrationId.equals("google")) {
      return new GoogleUser(oAuth2User, clientRegistration);
    } else if (registrationId.equals("naver")) {
      return new NaverUser(oAuth2User, clientRegistration);
    }
    return null;
  }

  protected void register(ProviderUser providerUser, OAuth2UserRequest userRequest) {
    User user = userRepository.findByUsername(providerUser.getUsername());
    if(user == null){
      String registrationId = userRequest.getClientRegistration().getRegistrationId();
      userService.register(registrationId, providerUser);
    }else{
      System.out.println("user = " + user);
    }
  }
}
