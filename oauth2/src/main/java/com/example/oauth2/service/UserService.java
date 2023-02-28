package com.example.oauth2.service;

import com.example.oauth2.model.ProviderUser;
import com.example.oauth2.model.User;
import com.example.oauth2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

  @Autowired
  private UserRepository userRepository;

  public void register(String registrationId, ProviderUser providerUser) {
    User user = User.builder()
        .registrationId(registrationId)
        .id(providerUser.getId())
        .username(providerUser.getUsername())
        .provider(providerUser.getProvider())
        .email(providerUser.getEmail())
        .authorities(providerUser.getAuthorities())
        .build();

    userRepository.register(user);
  }
}
