package org.omnifaces.security.jaspic;

public class AuthParameters {

	private String username;
	private String password;
	private Boolean rememberMe;
	private String authMethod;

	public AuthParameters username(String username) {
		setUsername(username);
		return this;
	}
	
	public AuthParameters password(String passWord) {
		setPassword(passWord);
		return this;
	}
	
	public AuthParameters rememberMe(boolean rememberMe) {
		setRememberMe(rememberMe);
		return this;
	}
	
	public AuthParameters authMethod(String authMethod) {
		setAuthMethod(authMethod);
		return this;
	}
	
	// Getters/setters
	
	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Boolean getRememberMe() {
		return rememberMe;
	}

	public void setRememberMe(Boolean rememberMe) {
		this.rememberMe = rememberMe;
	}

	public String getAuthMethod() {
		return authMethod;
	}

	public void setAuthMethod(String authMethod) {
		this.authMethod = authMethod;
	}

}