package com.example.oauth_server.controller;

import com.example.oauth_server.dto.JoinRequest;
import com.example.oauth_server.dto.LogoutRequest;
import com.example.oauth_server.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping
public class AuthController {

    private final UserService userService;

    @Resource(name = "tokenServices")
    private ConsumerTokenServices tokenServices;

    @Resource(name = "tokenStore")
    private TokenStore tokenStore;

    @PostMapping("/join")
    public ResponseEntity<Boolean> join(@RequestBody JoinRequest joinRequest) {
        log.info(":: join ::");

        return ResponseEntity.ok(userService.sigup(joinRequest));
    }

    @PostMapping("/revoke_token")
    public ResponseEntity<?> revokeToken(@RequestBody LogoutRequest logoutRequest) {
        log.info(":: revokeToken ::");

        tokenServices.revokeToken(logoutRequest.access_token());
        tokenStore.removeRefreshToken(new DefaultOAuth2RefreshToken(logoutRequest.refresh_token()));

        return ResponseEntity.ok("ok");
    }

    @GetMapping("/oauth2_join/{clientRegId}")
    public ResponseEntity<?> oauth2Join(@PathVariable("clientRegId") String clientRegId) {
        log.info(":: oauth2_join ::");
        log.info("clientRegId : {}", clientRegId);

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String authClientRegId = ((OAuth2AuthenticationToken)authentication).getAuthorizedClientRegistrationId();
        if (!StringUtils.equals(clientRegId, authClientRegId)) {
            // todo: 에러 처리
            return ResponseEntity.ok("fail");
        }

        return ResponseEntity.ok(userService.sigupFromOauth2(authentication));
    }
}
