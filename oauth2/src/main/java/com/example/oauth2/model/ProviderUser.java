package com.example.oauth2.model;

import java.util.List;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;

public interface ProviderUser {

  String getId();  //id 가져오기

  String getUsername(); //유저 이름 가져오기

  String getPassword(); //password 가져오기

  String getEmail();

  String getProvider();

  List<? extends GrantedAuthority> getAuthorities();

  Map<String, Object> getAttributes();
}
