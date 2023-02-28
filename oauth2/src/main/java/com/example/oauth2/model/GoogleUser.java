package com.example.oauth2.model;

import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class GoogleUser extends OAuth2ProviderUser {

  public GoogleUser(OAuth2User oAuth2User, ClientRegistration clientRegistration) {
    super(oAuth2User.getAttributes(), oAuth2User, clientRegistration);
  }

  @Override
  public String getId() {
    return (String) getAttributes().get("sub");//구글은 sub를 반환
  }

  @Override
  public String getUsername() {
    return (String) getAttributes().get("sub");
  }

}
