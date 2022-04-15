package com.example.oauth_server.controller;

import com.example.oauth_server.dto.JoinRequest;
import com.example.oauth_server.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {

    private final UserService userService;


    @PostMapping("/join")
    public ResponseEntity<Boolean> join(@RequestBody JoinRequest joinRequest) {
        return ResponseEntity.ok(userService.sigup(joinRequest));
    }
}
