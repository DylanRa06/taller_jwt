package com.krakedev.taller_jwt;

import java.util.Date;
import java.util.UUID;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtUtil {

    // Clave de ejemplo para el taller. JWT_SECRET permite usar una clave privada propia.
    private static final String CLAVE_SECRETA = System.getenv().getOrDefault(
            "JWT_SECRET", "EsUnaClaveSuperSecretaYMuyLarga1234567890!");
    private static final String EMISOR = "KrakeDevBackend";
    private static final long TIEMPO_EXPIRACION = 3600000;

    public static String generarToken(String username, String rol) {
        Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);
        long tiempoActual = System.currentTimeMillis();
        Date fechaExpiracion = new Date(tiempoActual + TIEMPO_EXPIRACION);

        return JWT.create()
                .withIssuer(EMISOR)
                .withSubject(username)
                .withJWTId(UUID.randomUUID().toString())
                .withIssuedAt(new Date(tiempoActual))
                .withExpiresAt(fechaExpiracion)
                .withClaim("rol", rol)
                .sign(algoritmo);
    }

    public static DecodedJWT validarToken(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        try {
            Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);
            JWTVerifier verificador = JWT.require(algoritmo).withIssuer(EMISOR).build();
            return verificador.verify(token);
        } catch (JWTVerificationException e) {
            System.out.println("Token inválido o expirado: " + e.getMessage());
            return null;
        }
    }
}
