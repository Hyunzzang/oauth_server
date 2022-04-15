package com.example.oauth_server.dto;

public record JoinRequest(
        String email,
        String password
) {
}
