package com.krakedev.taller_jwt.services;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class TokenBlackListService {

    private final Map<String, Instant> blacklist = new ConcurrentHashMap<>();

    public void invalidarToken(DecodedJWT token) {
        Instant ahora = Instant.now();
        blacklist.entrySet().removeIf(entrada -> !entrada.getValue().isAfter(ahora));
        blacklist.put(clave(token), token.getExpiresAt().toInstant());
    }

    public boolean estaInvalidado(DecodedJWT token) {
        Instant expiracion = blacklist.get(clave(token));
        return expiracion != null && expiracion.isAfter(Instant.now());
    }

    private String clave(DecodedJWT token) {
        // Identifica el contenido firmado de un JWT ya verificado.
        return token.getHeader() + "." + token.getPayload();
    }
}
