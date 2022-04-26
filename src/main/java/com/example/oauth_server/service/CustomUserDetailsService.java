package com.example.oauth_server.service;

import com.example.oauth_server.domain.User;
import com.example.oauth_server.repository.UserRepository;
import com.example.oauth_server.security.UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByEmail(username)
                .map(this::createUserDetails)
                .orElseThrow(() -> new IllegalArgumentException("유저 정보가 없습니다."));
    }

    private UserDetails createUserDetails(User user) {
        return new UserPrincipal(user.getId(), user.getEmail(), user.getPassword(),
                user.getName(), user.getImageUrl(), user.getProvider(),
                Collections.singletonList(user.getRole().getKey()).stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
    }
}
