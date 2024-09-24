package com.abc.restaurant.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class ContentController {
     
    @GetMapping("/login")
    public String login(){
        return "/registerandlogin/login";
    }

    @GetMapping("/req/signup")
    public String signup(){
        return "/registerandlogin/signup";
    }

    @GetMapping("/index")
    public String home(){
        return "/customerinterface/index";
    }
}

