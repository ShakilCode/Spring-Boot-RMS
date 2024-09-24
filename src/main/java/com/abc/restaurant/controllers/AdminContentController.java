package com.abc.restaurant.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class AdminContentController {
     
    @GetMapping("/adminlogin")
    public String adminlogin(){
        return "/adminregisterandlogin/adminlogin";
    }

    @GetMapping("/req/adminsignup")
    public String adminsignup(){
        return "/adminregisterandlogin/adminsignup";
    }

    @GetMapping("/admin")
    public String adminAddPage(){
        return "adminadd/admin";
    }


}
