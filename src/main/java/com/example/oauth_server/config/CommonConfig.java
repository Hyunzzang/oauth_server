package com.example.oauth_server.config;

import com.example.oauth_server.security.CustomAuthenticationSuccessHandler;
import com.example.oauth_server.security.oauth2.CustomOAuth2Provider;
import com.example.oauth_server.security.oauth2.CustomStatelessAuthorizationRequestRepository;
import com.example.oauth_server.security.oauth2.TokenAuthenticationFilter;
import com.example.oauth_server.service.CustomUserDetailsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class CommonConfig {

    private final RedisConnectionFactory redisConnectionFactory;
    private final CustomUserDetailsService customUserDetailsService;

    @Value("${custom.oauth2.kakao.redirect-uri}")
    private String kakaoRedirectUri;

    @Value("${custom.oauth2.kakao.scope}")
    private String kakaoScope;

    @Value("${custom.oauth2.kakao.client-name}")
    private String kakaoClientName;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());

        return objectMapper;
    }

    @Bean
    public TokenStore tokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setAccessTokenValiditySeconds(300);
        return defaultTokenServices;
    }

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter((RedisTokenStore)tokenStore());
    }

    @Bean
    public AuthorizationRequestRepository authorizationRequestRepository() {
//        return new CustomAuthorizationRequestRepository();
        return new CustomStatelessAuthorizationRequestRepository();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler(customUserDetailsService);
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(
            OAuth2ClientProperties oAuth2ClientProperties,
            @Value("${custom.oauth2.kakao.client-id}") String kakaoClientId,
            @Value("${custom.oauth2.kakao.client-secret}") String kakaoClientSecret) {
        List<ClientRegistration> registrations = oAuth2ClientProperties.getRegistration().keySet()
                .stream()
                .map(client -> getRegistration(oAuth2ClientProperties, client))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        registrations.add(CustomOAuth2Provider.KAKAO.getBuilder("kakao")
                .clientId(kakaoClientId)
                .clientSecret(kakaoClientSecret)
//                .redirectUri("http://localhost:8080/login/oauth2/code/kakao")
//                .scope("profile_nickname", "profile_image", "account_email")
//                .clientName(kakaoClientName)
//                .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    private ClientRegistration getRegistration(OAuth2ClientProperties clientProperties, String client) {
        if ("google".equals(client)) {
            OAuth2ClientProperties.Registration registration = clientProperties.getRegistration().get("google");
            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .scope("email", "profile").
                    build();
        }

        return null;
    }
}
