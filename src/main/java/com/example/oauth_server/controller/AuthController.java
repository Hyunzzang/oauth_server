package com.example.oauth_server.controller;

import com.example.oauth_server.dto.JoinRequest;
import com.example.oauth_server.dto.LogoutRequest;
import com.example.oauth_server.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

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
}
