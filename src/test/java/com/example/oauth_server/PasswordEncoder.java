package com.example.oauth_server;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;

public class PasswordEncoder {
    public static void main(String[] args) {
        org.springframework.security.crypto.password.PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        System.out.printf("123456 : %s\n", passwordEncoder.encode("123456"));
    }
}
