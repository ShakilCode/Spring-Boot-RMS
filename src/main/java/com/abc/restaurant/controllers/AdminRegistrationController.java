package com.abc.restaurant.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.abc.restaurant.models.AdminMyAppUser;
import com.abc.restaurant.models.AdminMyAppUserRepository;

@RestController
public class AdminRegistrationController {

    @Autowired
    private AdminMyAppUserRepository adminMyAppUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping(value="/req/adminsignup", consumes= "application/json")
    public AdminMyAppUser createUser(@RequestBody AdminMyAppUser user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return adminMyAppUserRepository.save(user);
    }
    
}
