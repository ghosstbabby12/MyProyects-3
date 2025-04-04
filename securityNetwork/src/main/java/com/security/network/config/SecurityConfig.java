package com.security.network.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Deshabilitar CSRF para permitir solicitudes POST
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/**").permitAll() // Permitir acceso a Actuator
                .anyRequest().permitAll() // Permitir todas las demás solicitudes
            )
            .formLogin(login -> login.disable()) // Deshabilitar formulario de login
            .httpBasic(httpBasic -> httpBasic.disable()); // Deshabilitar autenticación básica

        return http.build();
    }
}
