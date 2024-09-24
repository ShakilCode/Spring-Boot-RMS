package com.abc.restaurant.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class StaffContentController {
     
    @GetMapping("/stafflogin")
    public String stafflogin(){
        return "/staffregisterandlogin/stafflogin";
    }

    @GetMapping("/req/staffsignup")
    public String staffsignup(){
        return "/staffregisterandlogin/staffsignup";
    }


}
