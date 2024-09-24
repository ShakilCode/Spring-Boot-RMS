package com.abc.restaurant.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.abc.restaurant.models.AdminMyAppUserService;
import com.abc.restaurant.models.MyAppUserService;
import com.abc.restaurant.models.StaffMyAppUserService;

import lombok.AllArgsConstructor;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {

    // (DI) Pattern (@Autowired)
    @Autowired
    private final MyAppUserService appUserService;  // Regular user service

    @Autowired
    private final AdminMyAppUserService adminUserService;  // Admin service

    @Autowired
    private final StaffMyAppUserService staffMyAppUserService; // Staff service

    // UserDetailsService for regular users
    @Bean
    public UserDetailsService userDetailsService() {
        return appUserService;
    }

    // UserDetailsService for admins
    @Bean
    public UserDetailsService adminUserDetailsService() {
        return adminUserService;
    }

    // UserDetailsService for staff
    @Bean
    public UserDetailsService staffUserDetailsService() {
        return staffMyAppUserService;
    }


    // Strategy Pattern (AuthenticationProvider)
    @Bean
    public AuthenticationProvider userAuthenticationProvider() {
        // DaoAuthenticationProvider  used as a strategy for authentication
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // AuthenticationProvider for admins
    @Bean
    public AuthenticationProvider adminAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(adminUserDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // AuthenticationProvider for staff
    @Bean
    public AuthenticationProvider staffAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(staffUserDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // Password encoder
    @Bean  // Singleton Pattern (bean methods passwordEncoder)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Security filter chain for admin
    @Bean
    @Order(1)                                           // Template Method Pattern
    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(AbstractHttpConfigurer::disable)
             // If type any of this path it goes to the login page
            .securityMatcher("/admin/**", "/adminadd/**", "/adminadd/addfoodmenu/**", 
             "/adminaddlunch/addfoodmenulunch/**", "/adminadddinner/addfoodmenudinner/**", "/adminadddesserts/addfoodmenudesserts/**",
              "/adminadddrink/addfoodmenudrink/**", "/adminaddgallery/addfoodgallery/**", "/adminaddlunch/**",
              "/adminadddinner/**", "/adminadddesserts/**", "/adminadddrink/**", "/adminaddgallery/**", 
              "/customerinterfaceorderfood/adminvieworderfood/**", "/customerinterface/adminviewtablereservations/**",
               "/customerfeedback/adminviewfeedback/**", "/adminadd/googlemaps/**", "/adminlogin") // Apply to admin URLs
            .authenticationProvider(adminAuthenticationProvider()) // Use admin auth provider
            // Builder Pattern
            .formLogin(httpForm -> {
                httpForm.loginPage("/adminlogin").permitAll();
                httpForm.defaultSuccessUrl("/admin", true);
            })
            .authorizeHttpRequests(registry -> {
                registry.requestMatchers("/admin/**").authenticated();
                registry.requestMatchers("/req/adminsignup", "/css/**", "/js/**", "/images/**").permitAll();
                registry.anyRequest().authenticated();
            })
            .build();
    }
    
    // Security filter chain for users
    @Bean
    @Order(2)
    public SecurityFilterChain userSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(AbstractHttpConfigurer::disable)
             // If type any of this path it goes to the login page
            .securityMatcher("/index/**", "/customerinterface/about/**", "/customerinterface/menu/**", 
            "/customerinterface/blog/**", "/customerinterface/contact/**", "/customerfeedback/customeraddfeedback/**",
             "/customerinterface/reservation/**", "/customerinterface/**", "/customerviewmenu/customerviewbreakfastmenu/**", 
            "/customerviewmenu/customerviewlunchmenu/**", "/customerviewmenu/customerviewdinnermenu/**", 
            "/customerviewmenu/customerviewdrinkmenu/**", "/customerviewmenu/customerviewdessertsmenu/**", 
            "/customerviewmenu/customerviewgallery/**", 
            "/customerinterfaceorderfood/customerorderfood/**", "/customerinterfaceorderfood/**", 
            "/customerpayment/customermakepayment/**", "/customerpayment/**", "/customerinterface/blog-single/**", "/login") // Apply to user URLs
            .authenticationProvider(userAuthenticationProvider()) // Use user auth provider
            .formLogin(httpForm -> {
                httpForm.loginPage("/login").permitAll();
                httpForm.defaultSuccessUrl("/index", true);
            })
            .authorizeHttpRequests(registry -> {
                registry.requestMatchers("/index/**").authenticated();
                registry.requestMatchers("/req/signup", "/css/**", "/js/**", "/images/**").permitAll();
                registry.anyRequest().authenticated();
            })
            .build();
    }

    // Security filter chain for staff
    @Bean
    @Order(3)
    public SecurityFilterChain staffSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(AbstractHttpConfigurer::disable)
            // If type any of this path it goes to the login page
            .securityMatcher("/staffdashboard/staff/**", "/staffdashboard/viewaddbreakfastmenu/**", 
             "/staffdashboard/viewaddfoodmenulunch/**", "/staffdashboard/viewaddfoodmenudinner/**", 
             "/staffdashboard/viewaddfoodmenudesserts/**", "/staffdashboard/viewaddfoodmenudrink/**",
              "/staffdashboard/staffvieworderfood/**", "/staffdashboard/staffviewtablereservations/**",
              "/staffdashboard/googlemaps/**", "/stafflogin") // Apply to staff URLs
            .authenticationProvider(staffAuthenticationProvider()) // Use staff auth provider
            .formLogin(httpForm -> {
                httpForm.loginPage("/stafflogin").permitAll();
                httpForm.defaultSuccessUrl("/staffdashboard/staff", true); // Ensure this is correct
            })
            .authorizeHttpRequests(registry -> {
                registry.requestMatchers("/staffdashboard/staff/**").authenticated();
                registry.requestMatchers("/req/staffsignup", "/css/**", "/js/**", "/images/**").permitAll();
                registry.anyRequest().authenticated();
            })
            .build();
    }
}
