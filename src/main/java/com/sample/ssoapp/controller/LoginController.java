package com.sample.ssoapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class LoginController {


    @GetMapping("/")
    public String home(){
        return "home";
    }

    @GetMapping("/sso-login")
    public String login(){
        return "login";
    }
}
