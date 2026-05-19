package br.senac.tads.dsw.dadospessoais.seguranca;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	// =================================================
	// 1) ADICIONAR ESTE TRECHO NO CÓDIGO EXISTENTE
	// PARA INJETAR jwtFilter NO SecurityConfig
	private final JwtFilter jwtFilter;

	public SecurityConfig(JwtFilter jwtFilter) {
		this.jwtFilter = jwtFilter;
	}

	// =================================================
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.csrf(csrf -> csrf.disable())
			.headers(headers -> headers
				.frameOptions(frame -> frame.disable()))
			.sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.authorizeHttpRequests(auth -> auth
				.requestMatchers(HttpMethod.POST, "/login").permitAll()
				.requestMatchers("/h2-console/**").permitAll()
				.requestMatchers("/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**")
				.permitAll()
				// =================================================
				// 2) ADICIONAR ESTAS LINHAS NO CÓDIGO EXISTENTE
				// /me e os endpoints de acesso exigem autenticação (cobertos por anyRequest)
				.requestMatchers("/me").authenticated()
				// Permitir acesso aos arquivos das telas - adiantando config da etapa 7.7
				.requestMatchers("/*.html", "/*.css", "/*.js").permitAll()
				// =================================================
				.requestMatchers(HttpMethod.GET, "/pessoas", "/pessoas/**").permitAll()
				.requestMatchers(HttpMethod.POST, "/pessoas", "/pessoas/**").authenticated()
				.requestMatchers(HttpMethod.PUT, "/pessoas/**").authenticated()
				.requestMatchers(HttpMethod.DELETE, "/pessoas/**").authenticated()
				.anyRequest().authenticated()
			)
			// =================================================
			// 3) ADICIONAR ESTA LINHA NO CÓDIGO EXISTENTE
			// Registra o JwtFilter ANTES do filtro padrão de autenticação por username/senha.
			// Fluxo: JwtFilter extrai e valida o token → preenche o SecurityContextHolder
			// → os demais filtros e regras de autorização enxergam o usuário autenticado.
			.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
		// =================================================
		return http.build();
	}

	@Bean
	public AuthenticationManager authenticationManager(
		UserDetailsService userDetailsService,
		PasswordEncoder passwordEncoder) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
		provider.setPasswordEncoder(passwordEncoder);
		return new ProviderManager(provider);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
