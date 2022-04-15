package com.example.oauth_server.security;

public record OAuthToken(
    String access_token,
    String token_type,
    String refresh_token,
    long expires_in,
    String scope
){}
