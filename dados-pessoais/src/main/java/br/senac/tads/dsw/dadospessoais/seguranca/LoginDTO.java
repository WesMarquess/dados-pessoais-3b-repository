package br.senac.tads.dsw.dadospessoais.seguranca;

public class LoginDTO {

	private String username;
	private String senha;

	public LoginDTO() {

	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getSenha() {
		return senha;
	}

	public void setSenha(String senha) {
		this.senha = senha;
	}
}
