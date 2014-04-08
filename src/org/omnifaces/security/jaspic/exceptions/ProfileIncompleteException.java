package org.omnifaces.security.jaspic.exceptions;

public class ProfileIncompleteException extends Exception {

	private static final long serialVersionUID = 1L;

	private String reason;

	public ProfileIncompleteException(String reason) {
		this.reason = reason;
	}

	public ProfileIncompleteException(String reason, Throwable cause) {
		super(cause);
		this.reason = reason;
	}

	public String getReason() {
		return reason;
	}
	
}
