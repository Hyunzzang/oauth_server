package com.example.oauth_server.security.oauth2;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;


/**
 * OAuth2 로그인 실패시 처리 해야 할 것들
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

//    private final CustomAuthorizationRequestRepository authorizationRequestRepository;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        log.info(":: onAuthenticationFailure ::");

//        String targetUrl = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
//                .map(Cookie::getValue)
//                .orElse(("/"));
//        targetUrl = UriComponentsBuilder.fromUriString(targetUrl)
//                .queryParam("error", exception.getLocalizedMessage())
//                .build().toUriString();
//
//        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
//        getRedirectStrategy().sendRedirect(request, response, targetUrl);


        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"Authentication Failure\" }");
    }
}
