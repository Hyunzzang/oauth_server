package com.example.oauth_server.security.oauth2;

import com.example.oauth_server.util.CookieUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final RedisTokenStore tokenStore;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info(":: doFilterInternal ::");
        String token = getTokenFromRequest(request);
        log.info("Token: {}", token);

        if (org.apache.commons.lang3.StringUtils.isNotEmpty(token)) {
            OAuth2Authentication auth2Authentication = tokenStore.readAuthentication(token);
            if (Objects.isNull(auth2Authentication)) {
                // todo: 에러 처리
                filterChain.doFilter(request, response);
            }

            SecurityContextHolder.getContext().setAuthentication(auth2Authentication);
        }

        filterChain.doFilter(request, response);
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        } else {
            return CookieUtils.getCookie(request, "a_token").map(Cookie::getValue).orElse(null);
        }
    }
}
