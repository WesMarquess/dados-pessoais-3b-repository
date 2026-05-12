package br.senac.tads.dsw.dadospessoais.seguranca;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class LoginController {

	private final AuthenticationManager authenticationManager;
	private final JwtService jwtService;

	public LoginController(AuthenticationManager authenticationManager, JwtService jwtService) {
		this.authenticationManager = authenticationManager;
		this.jwtService = jwtService;
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginDTO dto) {

		try {
			Authentication auth = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
					dto.getUsername(), dto.getSenha()));

			UsuarioSistema usuarioSistema = (UsuarioSistema) auth.getPrincipal();

			String token = jwtService.gerarToken(usuarioSistema);
			return ResponseEntity.ok(Map.of("Token", token));
		} catch (BadCredentialsException e) {
			return ResponseEntity.
				status(HttpStatus.UNAUTHORIZED)
				.body(Map.of("erro", "Usuario ou senha inválidos"));
		}
	}
}
