package com.abc.restaurant.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.abc.restaurant.models.StaffMyAppUser;
import com.abc.restaurant.models.StaffMyAppUserRepository;

@RestController
public class StaffRegistrationController {

    @Autowired
    private StaffMyAppUserRepository staffMyAppUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping(value="/req/staffsignup", consumes= "application/json")
    public StaffMyAppUser createUser(@RequestBody StaffMyAppUser user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return staffMyAppUserRepository.save(user);
    }
    
}
