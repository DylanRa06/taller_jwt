package com.krakedev.taller_jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import com.krakedev.taller_jwt.services.TokenBlackListService;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, TokenBlackListService blacklistService)
            throws Exception {
        var matcher = PathPatternRequestMatcher.withDefaults();
        var rutasPublicas = new OrRequestMatcher(
                matcher.matcher(HttpMethod.POST, "/auth/login"),
                matcher.matcher(HttpMethod.POST, "/auth/registrar"));

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(excepciones -> excepciones.authenticationEntryPoint((request, response, error) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
                    response.setContentType("text/plain;charset=UTF-8");
                    response.getWriter().write(
                            "Acceso denegado: Debes proveer un token Bearer válido en la cabecera Authorization");
                }).accessDeniedHandler((request, response, error) -> {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("text/plain;charset=UTF-8");
                    response.getWriter().write("Acceso denegado: No tienes permiso para este recurso");
                }))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(rutasPublicas).permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new JwtAuthenticationFilter(blacklistService, rutasPublicas),
                        UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
