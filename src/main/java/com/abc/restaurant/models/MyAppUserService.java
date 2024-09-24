package com.abc.restaurant.models;



import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;



@Service
public class MyAppUserService implements UserDetailsService {

    @Autowired
    private MyAppUserRepository myAppUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        MyAppUser user = myAppUserRepository.findByUserName(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new User(user.getUserName(), user.getPassword(), new ArrayList<>());
    }
}
