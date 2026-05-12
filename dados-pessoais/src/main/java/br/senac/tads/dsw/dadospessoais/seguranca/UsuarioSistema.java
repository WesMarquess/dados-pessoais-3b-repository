package br.senac.tads.dsw.dadospessoais.seguranca;

import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

public class UsuarioSistema implements UserDetails {

	private final String username;
	private final String password;
	private final List<GrantedAuthority> authority;

	public UsuarioSistema(String username, String password, List<GrantedAuthority> authority) {
		this.username = username;
		this.password = password;
		this.authority = authority;
	}

	@Override
	public boolean isAccountNonExpired() {
		return UserDetails.super.isAccountNonExpired();
	}

	@Override
	public boolean isAccountNonLocked() {
		return UserDetails.super.isAccountNonLocked();
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return UserDetails.super.isCredentialsNonExpired();
	}

	@Override
	public boolean isEnabled() {
		return UserDetails.super.isEnabled();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authority;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}
}
