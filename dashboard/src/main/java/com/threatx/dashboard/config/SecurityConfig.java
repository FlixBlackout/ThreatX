package com.threatx.dashboard.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authz -> authz
                // Allow access to static resources
                .requestMatchers(
                    new AntPathRequestMatcher("/css/**"),
                    new AntPathRequestMatcher("/js/**"),
                    new AntPathRequestMatcher("/images/**"),
                    new AntPathRequestMatcher("/webjars/**"),
                    new AntPathRequestMatcher("/favicon.ico")
                ).permitAll()
                // Allow access to common endpoints
                .requestMatchers(
                    new AntPathRequestMatcher("/"),
                    new AntPathRequestMatcher("/health"),
                    new AntPathRequestMatcher("/error"),
                    new AntPathRequestMatcher("/h2-console/**")
                ).permitAll()
                // Allow access to API endpoints (can be secured with JWT later)
                .requestMatchers(
                    new AntPathRequestMatcher("/api/**")
                ).permitAll()
                // All other requests need authentication
                .anyRequest().permitAll() // For testing purposes, permit all
            )
            .csrf(AbstractHttpConfigurer::disable) // Disable CSRF for testing
            .headers(headers -> headers
                .frameOptions().disable() // Allow H2 console in iframe
            );
        
        return http.build();
    }
}