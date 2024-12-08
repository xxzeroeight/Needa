package com.market.needa.presentation.user.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserViewController {

    @GetMapping("/login")
    public String login() {
        return "forward:/user/login.html";
    }

    @GetMapping("/signup")
    public String signup() {
        return "forward:/user/signup.html";
    }
}
