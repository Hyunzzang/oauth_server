package com.example.oauth_server.controller;

import com.example.oauth_server.util.CookieUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/msg")
    public ResponseEntity<String> msg() {
        return ResponseEntity.ok("test_ok");
    }

    @GetMapping("/home")
    public ResponseEntity<String> home(HttpServletRequest request) {
        String accessToken = CookieUtils.getCookie(request, "a_token").map(Cookie::getValue).orElse("");
        String refreshToken = CookieUtils.getCookie(request, "r_token").map(Cookie::getValue).orElse("");

        String body = String.format("AccessToken : %s, RefreshToken : %s", accessToken, refreshToken);

        return ResponseEntity.ok(body);
    }

    @GetMapping("/user")
    public ResponseEntity<?> user() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ResponseEntity.ok(authentication);
    }
}
