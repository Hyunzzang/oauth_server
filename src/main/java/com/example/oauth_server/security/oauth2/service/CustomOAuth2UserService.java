package com.example.oauth_server.security.oauth2.service;

import com.example.oauth_server.domain.AuthProvider;
import com.example.oauth_server.domain.User;
import com.example.oauth_server.repository.UserRepository;
import com.example.oauth_server.security.UserPrincipal;
import com.example.oauth_server.security.oauth2.user.OAuth2UserInfo;
import com.example.oauth_server.security.oauth2.user.OAuth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * 이 클래스 소셜로그인 이후 가져온 사용자의 정보(email, name, picture 등)들을 기반으로
 * 가입 및 정보수정, 세션 저장 등의 기능을 지원함.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info(":: loadUser ::");

        OAuth2User oAuth2User = super.loadUser(userRequest);

        return processOAuth2User(userRequest, oAuth2User);
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(), oAuth2User.getAttributes());
        if (StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
            // todo: throw exception 처리 해야함.
        }

        Optional<User> savedUser = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user = null;
        if (savedUser.isPresent()) {
            user = updateExistingUser(savedUser.get(), oAuth2UserInfo);
        } else {
            // todo: user 정보가 없을 경우 에러 처리
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

//        User user = savedUser.map(u -> updateExistingUser(u, oAuth2UserInfo))
//                .orElse(registerNewUser(oAuth2UserRequest, oAuth2UserInfo));

        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private User registerNewUser(OAuth2UserRequest userRequest, OAuth2UserInfo oAuth2UserInfo) {
        User user = User.builder()
                .email(oAuth2UserInfo.getEmail())
                .name(oAuth2UserInfo.getName())
                .imageUrl(oAuth2UserInfo.getImageUrl())
                .provider(AuthProvider.valueOf(userRequest.getClientRegistration().getRegistrationId()))
                .providerId(oAuth2UserInfo.getId())
                .build();

        // todo: 여기서 유저정보를 저장 않고 다른 곳에서 회원 가입 처리를 하자.
        return user;
        //return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
        if (!StringUtils.equals(existingUser.getName(), oAuth2UserInfo.getName())
                || !StringUtils.equals(existingUser.getImageUrl(), oAuth2UserInfo.getImageUrl())) {
            return userRepository.save(existingUser.update(oAuth2UserInfo.getName(), oAuth2UserInfo.getImageUrl()));
        }

        return existingUser;
    }
}
