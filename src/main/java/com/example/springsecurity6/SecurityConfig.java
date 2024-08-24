package com.example.springsecurity6;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
//                .loginPage("/loginPage")
                    .loginProcessingUrl("/loginProc")
                    .defaultSuccessUrl("/", true)
                    .failureForwardUrl("/login?error")
                    .usernameParameter("userId")
                    .passwordParameter("passwd")
                    .successHandler((request, response, authentication) -> {
                        System.out.println("authentication = " + authentication);
                        response.sendRedirect("/home");
                    })
                    .failureHandler((request, response, exception) -> {
                        System.out.println("exception = " + exception.getMessage());
                        response.sendRedirect("/login");
                    })
                    .permitAll()
            );
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}2222")
                .roles("USER")
                .build();
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}3333")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user, user1);
    }


}

