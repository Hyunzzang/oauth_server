package com.example.oauth_server.domain;

import java.util.Objects;

public enum AuthProvider {
    local,
    google;

    public static AuthProvider of(String providerName) {
        AuthProvider authProvider = AuthProvider.valueOf(providerName);
        if (Objects.isNull(authProvider)) {
            // todo: 에러처리
            return AuthProvider.local;
        }

        return authProvider;
    }
}
