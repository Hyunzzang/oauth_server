package com.example.oauth_server.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Slf4j
@Controller
public class LoginController {

    @GetMapping("/custom_login")
    public String getLoginPage(Model model) {
        return "custom_login";
    }

    @GetMapping("/loginSuccess")
    public String loginComplete() {
        log.info(":: /loginSuccess - loginComplete ::");

        return "redirect:/api/test/home";
    }
}
