package org.omnifaces.security.jaspic;

public class AuthParameters {

	private String userName;
	private String password;
	private Boolean rememberMe;
	private String authMethod;

	public AuthParameters userName(String userName) {
		setUserName(userName);
		return this;
	}
	
	public AuthParameters passWord(String passWord) {
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
	
	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
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
