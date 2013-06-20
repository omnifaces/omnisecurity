package org.omnifaces.security.jaspic;

public class RegistrationException extends Exception {

	private static final long serialVersionUID = 5180498365785959486L;

	private String reason;

	public RegistrationException(String reason) {
		this.reason = reason;
	}

	public RegistrationException(String reason, Throwable cause) {
		super(cause);
		this.reason = reason;
	}

	public String getReason() {
		return reason;
	}

}
