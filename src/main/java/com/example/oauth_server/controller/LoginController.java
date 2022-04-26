package com.example.oauth_server.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

    @GetMapping("/custom_login")
    public String getLoginPage(Model model) {
        return "custom_login";
    }
}
