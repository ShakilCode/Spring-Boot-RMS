package com.abc.restaurant.models;



import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;



@Service
public class StaffMyAppUserService implements UserDetailsService {

    @Autowired
    private StaffMyAppUserRepository staffMyAppUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        StaffMyAppUser user = staffMyAppUserRepository.findByUserName(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new User(user.getUserName(), user.getPassword(), new ArrayList<>());
    }
}
