package com.example.oauth_server.dto;

public record LogoutRequest(
        String access_token,
        String refresh_token) {
}
