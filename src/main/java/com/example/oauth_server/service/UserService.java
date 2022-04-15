package com.example.oauth_server.service;

import com.example.oauth_server.domain.AuthProvider;
import com.example.oauth_server.domain.Role;
import com.example.oauth_server.domain.User;
import com.example.oauth_server.dto.JoinRequest;
import com.example.oauth_server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public boolean sigup(JoinRequest joinRequest) {
        if (userRepository.existsByEmail(joinRequest.email())) {
            throw new IllegalArgumentException("이미 가입된 이메일 입니다.");
        }

        userRepository.save(User.builder()
                .email(joinRequest.email())
                .password(passwordEncoder.encode(joinRequest.password()))
                .role(Role.USER)
                .provider(AuthProvider.local)
                .build()).getId();

        return true;
    }
}
