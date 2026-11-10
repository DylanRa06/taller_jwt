package com.krakedev.taller_jwt.controllers;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.taller_jwt.JwtUtil;
import com.krakedev.taller_jwt.entidades.Usuario;
import com.krakedev.taller_jwt.repositories.UsuarioRepository;
import com.krakedev.taller_jwt.services.TokenBlackListService;
import com.krakedev.taller_jwt.services.UsuarioService;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UsuarioService usuarioService;
    private final UsuarioRepository usuarioRepository;

    private final TokenBlackListService blacklistService;

    public AuthController(UsuarioService usuarioService, UsuarioRepository usuarioRepository,
            TokenBlackListService blacklistService) {
        this.usuarioService = usuarioService;
        this.usuarioRepository = usuarioRepository;
        this.blacklistService = blacklistService;
    }

    @PostMapping("/registrar")
    public ResponseEntity<?> registrar(@RequestBody Usuario usuario) {
        try {
            Usuario usuarioNuevo = usuarioService.guardar(usuario);
            return ResponseEntity.status(HttpStatus.CREATED).body(usuarioNuevo);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al registrar usuario");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales) {
        String username = credenciales.get("username");
        String password = credenciales.get("password");
        boolean autenticado = usuarioService.autenticar(username, password);

        if (autenticado) {
            Usuario usuario = usuarioRepository.findByUsername(username).orElseThrow();
            String token = JwtUtil.generarToken(usuario.getUsername(), usuario.getRol());
            return ResponseEntity.ok(Map.of("token", token));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Usuario o contraseña incorrecta");
    }

    @GetMapping("/perfil")
    public ResponseEntity<?> verPerfil(Authentication autenticacion) {
        String autoridad = autenticacion.getAuthorities().iterator().next().getAuthority();
        return ResponseEntity.ok(Map.of(
                "Mensaje", "Bienvenido al sistema protegido por Spring Security",
                "Usuario", autenticacion.getName(),
                "Rol", autoridad.substring("ROLE_".length()),
                "rol_detectado", autoridad,
                "Estatus", "Autenticado Exitosamente"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(Authentication autenticacion) {
        blacklistService.invalidarToken((DecodedJWT) autenticacion.getDetails());
        return ResponseEntity.ok(Map.of("Mensaje", "Sesión cerrada exitosamente. Token invalidado"));
    }

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> adminDashboard(Authentication autenticacion) {
        return ResponseEntity.ok(Map.of(
                "Mensaje", "Bienvenido al panel de administradores",
                "admin", autenticacion.getName()));
    }
}
