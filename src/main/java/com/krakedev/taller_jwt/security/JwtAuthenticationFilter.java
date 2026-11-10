package com.krakedev.taller_jwt.security;

import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.taller_jwt.JwtUtil;
import com.krakedev.taller_jwt.services.TokenBlackListService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final TokenBlackListService blacklistService;
    private final RequestMatcher rutasPublicas;

    public JwtAuthenticationFilter(TokenBlackListService blacklistService, RequestMatcher rutasPublicas) {
        this.blacklistService = blacklistService;
        this.rutasPublicas = rutasPublicas;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return rutasPublicas.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String cabecera = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (cabecera == null || !cabecera.regionMatches(true, 0, "Bearer ", 0, 7)) {
            filterChain.doFilter(request, response);
            return;
        }

        DecodedJWT token = JwtUtil.validarToken(cabecera.substring(7));
        if (token == null || token.getExpiresAt() == null
                || token.getSubject() == null || token.getSubject().isBlank()) {
            rechazar(response, "Acceso denegado: Token inválido o expirado");
            return;
        }

        String rol = token.getClaim("rol").asString();
        if (rol == null || rol.isBlank()) {
            rechazar(response, "Acceso denegado: Token inválido o expirado");
            return;
        }
        if (blacklistService.estaInvalidado(token)) {
            rechazar(response, "Acceso denegado: Sesión cerrada");
            return;
        }

        var autoridad = new SimpleGrantedAuthority("ROLE_" + rol);
        var autenticacion = UsernamePasswordAuthenticationToken.authenticated(
                token.getSubject(), null, List.of(autoridad));
        autenticacion.setDetails(token);
        var contexto = SecurityContextHolder.createEmptyContext();
        contexto.setAuthentication(autenticacion);
        SecurityContextHolder.setContext(contexto);

        filterChain.doFilter(request, response);
    }

    private void rechazar(HttpServletResponse response, String mensaje) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"");
        response.setContentType("text/plain;charset=UTF-8");
        response.getWriter().write(mensaje);
    }
}
