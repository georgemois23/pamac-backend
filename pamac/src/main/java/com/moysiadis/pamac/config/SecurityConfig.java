package com.moysiadis.pamac.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())  // Disable CSRF protection (for testing, enable it in production)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/user/add", "/user/getAll").permitAll()  // Publicly accessible endpoints
                        .anyRequest().authenticated()  // All other endpoints require authentication
                )
                .httpBasic(withDefaults());  // Enable basic authentication with default settings

        return http.build();
    }
}
