package br.senac.tads.dsw.dadospessoais.seguranca;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

	@Value("${jwt.secret}")
	private String jwtScret;

	@Value("${jwt.expiracao-segundos:3600}")
	private Long expiracaoSegundos;

	public String gerarToken(UsuarioSistema usuarioSistema) {
		List<String> roles = new ArrayList<>();

		for (GrantedAuthority authority : usuarioSistema.getAuthorities()) {
			roles.add(authority.getAuthority());
		}

		Instant agora = Instant.now();
		Instant expiracao = agora.plusSeconds(expiracaoSegundos);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject(usuarioSistema.getUsername())
			.issuer("dados-pessoais-api")
			.issueTime(Date.from(agora))
			.expirationTime(Date.from(expiracao))
			.claim("roles", roles)
			.build();

		return jwtEncode(claimsSet);
	}

	private String jwtEncode(JWTClaimsSet claims) {
		try {
			byte[] keyBites = MessageDigest.getInstance("SHA-256")
				.digest(jwtScret.getBytes((StandardCharsets.UTF_8)));
			MACSigner signer = new MACSigner(keyBites);

			SignedJWT jwt = new SignedJWT(
				new JWSHeader(JWSAlgorithm.HS256),
				claims
			);

			jwt.sign(signer);

			return jwt.serialize();

		} catch (JOSEException | NoSuchAlgorithmException e) {
			throw new RuntimeException("Erro ao assinar token JWT", e);
		}
	}
}
