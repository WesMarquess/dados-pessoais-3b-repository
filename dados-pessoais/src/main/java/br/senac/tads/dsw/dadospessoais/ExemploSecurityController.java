package br.senac.tads.dsw.dadospessoais;

import br.senac.tads.dsw.dadospessoais.seguranca.UsuarioSistema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SecurityRequirement(name = "bearerJwt")
public class ExemploSecurityController {

	private final UserDetailsService userDetailsService;

	public ExemploSecurityController(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@GetMapping("/me")
	public UsuarioSistema obterDadosUsuariosLogado(Authentication auth) {
		String username = (String) auth.getPrincipal();
		return (UsuarioSistema) userDetailsService.loadUserByUsername(username);
	}

	public record MensagemRoleDto(String usuario, String mensagem) {
	}

	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/acesso/admin")
	public MensagemRoleDto mensagemAdmin(Authentication auth) {
		return new MensagemRoleDto(
			(String) auth.getPrincipal(),
			"mensagem para usuarios com role ADMIN");
	}

	@PreAuthorize("hasRole('GERENTE')")
	@GetMapping("/acesso/gerente")
	public MensagemRoleDto mensagemGerente(Authentication auth) {
		return new MensagemRoleDto(
			(String) auth.getPrincipal(),
			"Mensagem para o usuario com role GERENTE");
	}

	@PreAuthorize("hasRole('USER')")
	@GetMapping("/acesso/user")
	public MensagemRoleDto mensagemUser(Authentication auth) {
		return new MensagemRoleDto(
			(String) auth.getPrincipal(),
			"Mensagem para o usuario com role USUARIO"
		);
	}
}
