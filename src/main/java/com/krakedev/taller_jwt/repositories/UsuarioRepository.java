package com.krakedev.taller_jwt.repositories;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.krakedev.taller_jwt.entidades.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Integer> {

    Optional<Usuario> findByUsername(String username);
}
