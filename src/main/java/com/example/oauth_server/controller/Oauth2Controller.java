package com.example.oauth_server.controller;

import com.example.oauth_server.dto.RefreshTokenRequest;
import com.example.oauth_server.security.OAuthToken;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/oauth2")
public class Oauth2Controller {
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    @GetMapping(value = "/callback")
    public OAuthToken callbackSocial(@RequestParam String code) throws JsonProcessingException {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("grant_type", "authorization_code");
        params.add("redirect_uri", "http://localhost:8080/oauth2/callback");

        return requestedOauthToken(params);
    }

    @PostMapping(value = "/token/refresh")
    public OAuthToken refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) throws JsonProcessingException {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("refresh_token", refreshTokenRequest.refreshToken());
        params.add("grant_type", "refresh_token");

        return requestedOauthToken(params);
    }

    private OAuthToken requestedOauthToken(MultiValueMap<String, String> params) throws JsonProcessingException {
        final String credentials = "testapp:123456";
        String encodedCredentials = new String(Base64.encodeBase64(credentials.getBytes()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.add("Authorization", "Basic " + encodedCredentials);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:8080/oauth/token", request, String.class);
        if (response.getStatusCode() == HttpStatus.OK) {
            return objectMapper.readValue(response.getBody(), OAuthToken.class);
        }
        return null;
    }
}
