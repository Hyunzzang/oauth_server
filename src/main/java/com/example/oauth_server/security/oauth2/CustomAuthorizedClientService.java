//package com.example.oauth_server.security.oauth2;
//
//import com.example.oauth_server.repository.UserRepository;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
//import org.springframework.stereotype.Component;
//
//@Slf4j
//@Component
//@RequiredArgsConstructor
//public class CustomAuthorizedClientService implements OAuth2AuthorizedClientService {
//
//    private final UserRepository userRepository;
//
//    @Override
//    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
//        log.info(":: loadAuthorizedClient ::");
//        log.info("clientRegistrationId: {}", clientRegistrationId);
//        log.info("principalName: {}", principalName);
//        return null;
//    }
//
//    @Override
//    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
//        log.info(":: saveAuthorizedClient ::");
//        log.info("principal.getName: {}", principal.getName());
//    }
//
//    @Override
//    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
//        log.info(":: removeAuthorizedClient ::");
//        log.info("clientRegistrationId: {}", clientRegistrationId);
//        log.info("principalName: {}", principalName);
//    }
//}
