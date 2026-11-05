package com.krakedev.taller_jwt.services;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.stereotype.Service;
import com.krakedev.taller_jwt.entidades.Usuario;
import com.krakedev.taller_jwt.repositories.UsuarioRepository;

@Service
public class UsuarioService {

    private final UsuarioRepository repository;

    public UsuarioService(UsuarioRepository repository) {
        this.repository = repository;
    }

    public Usuario guardar(Usuario usuario) {
        if (usuario.getUsername() == null || usuario.getUsername().isBlank()
                || usuario.getPassword() == null || usuario.getPassword().isBlank()
                || usuario.getRol() == null || usuario.getRol().isBlank()) {
            throw new IllegalArgumentException("Username, password y rol son obligatorios");
        }
        if (usuario.getPassword().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new IllegalArgumentException("La contraseña no debe superar 72 bytes");
        }
        usuario.setId(null);
        usuario.setPassword(BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt()));
        return repository.save(usuario);
    }

    public boolean autenticar(String username, String password) {
        if (username == null || password == null
                || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            return false;
        }
        Optional<Usuario> usuarioEncontrado = repository.findByUsername(username);
        if (usuarioEncontrado.isPresent()) {
            Usuario usuario = usuarioEncontrado.get();
            return BCrypt.checkpw(password, usuario.getPassword());
        }
        return false;
    }
}
