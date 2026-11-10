package com.krakedev.taller_jwt;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.krakedev.taller_jwt.repositories.UsuarioRepository;
import tools.jackson.databind.json.JsonMapper;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TallerJwtApplicationTests {

    @LocalServerPort
    private int port;

    @Autowired
    private UsuarioRepository repository;

    private final HttpClient client = HttpClient.newHttpClient();
    private final JsonMapper mapper = JsonMapper.builder().build();

    private HttpResponse<String> post(String ruta, String body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + ruta))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> perfil(String auth) throws Exception {
        return peticionProtegida("GET", "/auth/perfil", auth);
    }

    private HttpResponse<String> peticionProtegida(String metodo, String ruta, String auth) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(
                URI.create("http://localhost:" + port + ruta))
                .method(metodo, HttpRequest.BodyPublishers.noBody());
        if (auth != null) {
            request.header("Authorization", auth);
        }
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void registrarAutenticarYConsultarPerfil() throws Exception {
        HttpResponse<String> registro = post("/auth/registrar",
                "{\"username\":\"dylan_test\",\"password\":\"ClavePrueba123\",\"rol\":\"ADMIN\"}");
        assertEquals(201, registro.statusCode());
        assertFalse(mapper.readTree(registro.body()).has("password"));
        var usuario = repository.findByUsername("dylan_test").orElseThrow();
        assertNotEquals("ClavePrueba123", usuario.getPassword());
        assertTrue(BCrypt.checkpw("ClavePrueba123", usuario.getPassword()));

        HttpResponse<String> login = post("/auth/login",
                "{\"username\":\"dylan_test\",\"password\":\"ClavePrueba123\"}");
        assertEquals(200, login.statusCode());
        String token = mapper.readTree(login.body()).get("token").asString();
        assertEquals("dylan_test", JwtUtil.validarToken(token).getSubject());
        assertEquals("ADMIN", JwtUtil.validarToken(token).getClaim("rol").asString());
        HttpResponse<String> respuesta = perfil("Bearer " + token);
        assertEquals(200, respuesta.statusCode());
        assertEquals("dylan_test", mapper.readTree(respuesta.body()).get("Usuario").asString());
        assertEquals("ROLE_ADMIN", mapper.readTree(respuesta.body()).get("rol_detectado").asString());
        assertEquals(401, post("/auth/login",
                "{\"username\":\"dylan_test\",\"password\":\"incorrecta\"}").statusCode());
    }

    @Test
    void rechazarCredencialesIncompletasYUsuarioInexistente() throws Exception {
        assertEquals(401, post("/auth/login", "{}").statusCode());
        assertEquals(401, post("/auth/login",
                "{\"username\":\"no_existe\",\"password\":\"incorrecta\"}").statusCode());
        assertEquals(400, post("/auth/registrar", "{\"username\":\"incompleto\"}").statusCode());
    }

    @Test
    void rechazarPerfilSinBearerOConTokenInvalido() throws Exception {
        assertEquals(401, perfil(null).statusCode());
        assertEquals(401, perfil("Basic abc").statusCode());
        assertEquals(401, perfil("Bearer token-invalido").statusCode());
        String token = JwtUtil.generarToken("dylan", "ADMIN");
        String[] partes = token.split("\\.");
        char primerCaracter = partes[2].charAt(0);
        String alterado = partes[0] + "." + partes[1] + "."
                + (primerCaracter == 'A' ? "B" : "A") + partes[2].substring(1);
        assertEquals(401, perfil("Bearer " + alterado).statusCode());
    }

    @Test
    void rechazarTokensExpiradosODeOtroEmisor() throws Exception {
        String clave = System.getenv().getOrDefault("JWT_SECRET",
                "EsUnaClaveSuperSecretaYMuyLarga1234567890!");
        Algorithm algoritmo = Algorithm.HMAC256(clave);
        String expirado = JWT.create().withIssuer("KrakeDevBackend").withSubject("dylan")
                .withClaim("rol", "ADMIN").withExpiresAt(new Date(System.currentTimeMillis() - 60000))
                .sign(algoritmo);
        assertNull(JwtUtil.validarToken(expirado));
        assertEquals(401, perfil("Bearer " + expirado).statusCode());
        String otroEmisor = JWT.create().withIssuer("OtroEmisor").withSubject("dylan")
                .withClaim("rol", "ADMIN").withExpiresAt(new Date(System.currentTimeMillis() + 60000))
                .sign(algoritmo);
        assertEquals(401, perfil("Bearer " + otroEmisor).statusCode());
    }
    @Test
    void permitirDashboardSoloAlAdministrador() throws Exception {
        String admin = registrarYObtenerToken("admin_dashboard", "ADMIN");
        String usuario = registrarYObtenerToken("usuario_dashboard", "USER");

        assertEquals(401, peticionProtegida("GET", "/auth/dashboard", null).statusCode());
        var perfilUsuario = perfil("Bearer " + usuario);
        assertEquals(200, perfilUsuario.statusCode());
        assertEquals("ROLE_USER", mapper.readTree(perfilUsuario.body()).get("rol_detectado").asString());
        assertEquals(403, peticionProtegida("GET", "/auth/dashboard", "Bearer " + usuario).statusCode());

        var panel = peticionProtegida("GET", "/auth/dashboard", "Bearer " + admin);
        assertEquals(200, panel.statusCode());
        assertEquals("admin_dashboard", mapper.readTree(panel.body()).get("admin").asString());
    }

    @Test
    void cerrarSesionRevocaSoloElTokenPresentado() throws Exception {
        String token = registrarYObtenerToken("admin_logout", "ADMIN");
        String segundoToken = login("admin_logout");
        assertNotEquals(token, segundoToken);
        assertEquals(200, perfil("Bearer " + token).statusCode());
        assertEquals(401, peticionProtegida("POST", "/auth/logout", null).statusCode());
        assertEquals(401, peticionProtegida("POST", "/auth/logout", "Bearer token-invalido").statusCode());

        var cierre = peticionProtegida("POST", "/auth/logout", "Bearer " + token);
        assertEquals(200, cierre.statusCode());
        var rechazado = perfil("Bearer " + token);
        assertEquals(401, rechazado.statusCode());
        assertEquals("Acceso denegado: Sesión cerrada", rechazado.body());
        assertEquals(401, peticionProtegida("GET", "/auth/dashboard", "Bearer " + token).statusCode());
        assertEquals(200, perfil("Bearer " + segundoToken).statusCode());
        assertEquals(200, perfil("Bearer " + login("admin_logout")).statusCode());
    }

    private String registrarYObtenerToken(String username, String rol) throws Exception {
        var registro = post("/auth/registrar", """
                {"username":"%s","password":"ClavePrueba123","rol":"%s"}
                """.formatted(username, rol));
        assertEquals(201, registro.statusCode());
        return login(username);
    }

    private String login(String username) throws Exception {
        var login = post("/auth/login", """
                {"username":"%s","password":"ClavePrueba123"}
                """.formatted(username));
        assertEquals(200, login.statusCode());
        return mapper.readTree(login.body()).get("token").asString();
    }
}
