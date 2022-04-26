package com.example.oauth_server.service;

import com.example.oauth_server.domain.AuthProvider;
import com.example.oauth_server.domain.Role;
import com.example.oauth_server.domain.User;
import com.example.oauth_server.dto.JoinRequest;
import com.example.oauth_server.repository.UserRepository;
import com.example.oauth_server.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public boolean sigup(JoinRequest joinRequest) {
        registerUser(joinRequest.email(), joinRequest.password(), null, null, AuthProvider.local);

        return true;
    }

    public User sigupFromOauth2(UserPrincipal userPrincipal) {
        return registerUser(userPrincipal.getEmail(), null,
                userPrincipal.getName(), userPrincipal.getImgUrl(), userPrincipal.getProvider());
    }

    private User registerUser(String email, String password, String name, String imgUrl, AuthProvider authProvider) {
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("이미 가입된 이메일 입니다.");
        }

        return userRepository.save(User.builder()
                .email(email)
                .password(Objects.isNull(password) ? null : passwordEncoder.encode(password))
                .name(name)
                .imageUrl(imgUrl)
                .role(Role.USER)
                .provider(authProvider)
                .build());
    }
}
