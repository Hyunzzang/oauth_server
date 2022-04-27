package com.example.oauth_server.security.oauth2;

import com.example.oauth_server.config.OAuthConstant;
import com.example.oauth_server.domain.User;
import com.example.oauth_server.repository.UserRepository;
import com.example.oauth_server.security.UserPrincipal;
import com.example.oauth_server.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Serializable;
import java.util.*;

/**
 * OAuth2 로그인 성공후 처리 해야 할 것들
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final DefaultTokenServices tokenServices;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        log.info(":: onAuthenticationSuccess() ::");
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        String email =  userPrincipal.getEmail();
        String userName = userPrincipal.getName();
        String clientRegId = ((OAuth2AuthenticationToken)authentication).getAuthorizedClientRegistrationId();
        log.info("Authentication : {}", authentication);
        log.info("Authentication name : {}", email);
        log.info("Authentication clientRegId : {}", clientRegId);

        OAuth2AccessToken oAuth2AccessToken = tokenServices.createAccessToken(
                new OAuth2Authentication(makeOAuth2Request(email, ((OAuth2AuthenticationToken)authentication).getAuthorities()), authentication));
        log.info("accessToken: {}", oAuth2AccessToken.getValue());
        log.info("refreshToken: {}", oAuth2AccessToken.getRefreshToken().getValue());

        CookieUtils.addCookie(response, "a_token", oAuth2AccessToken.getValue(), 60);
        CookieUtils.addCookie(response, "r_token", oAuth2AccessToken.getRefreshToken().getValue(), 60);

        String targetUrl = targetUrl(email, clientRegId);
        log.info("targetUrl : {}", targetUrl);
        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private OAuth2Request makeOAuth2Request(String email, Collection<GrantedAuthority> authorities) {
        Map<String, String> requestParameters = new HashMap<>();
        requestParameters.put("username", email);
        requestParameters.put("scopes", "read,write,email,profile");
        requestParameters.put("grant_type", "authorization_code");

        Map<String, Serializable> extensionProperties = new HashMap<>();

        boolean approved = true;
        Set<String> responseTypes = new HashSet<>();
        responseTypes.add("code");

        List<String> scopes = Arrays.asList("read", "write", "email", "profile");

        // Authorities
//        List<GrantedAuthority> authorities = new ArrayList<>();
//        authorities.add(new SimpleGrantedAuthority(Role.USER.getKey()));

        return new OAuth2Request(requestParameters, "testapp", authorities, approved,
                new HashSet<>(scopes), new HashSet<>(Arrays.asList(OAuthConstant.RESOURCE_ID)), null, responseTypes, extensionProperties);
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        CookieUtils.deleteCookie(request, response, OAuthConstant.OAUTH_COOKIE_NAME);
    }

    private String targetUrl(String email, String clientRegId) {
        Optional<User> savedUser = userRepository.findByEmail(email);
        // 회원 정보가 있으면 홈 화면으로 없으면 가입 페이지로
        if (savedUser.isPresent()) {
            return "http://localhost:8080/api/test/home";
        } else {
            return "http://localhost:8080/oauth2_join/" + clientRegId;
        }
    }
}
