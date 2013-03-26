package org.omnifaces.security.jaspic;

import static javax.security.auth.message.AuthStatus.FAILURE;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;

public class AuthResult {

	private AuthStatus authStatus = FAILURE;
	private Exception exception;

	public AuthStatus getAuthStatus() {
		return authStatus;
	}

	public void setAuthStatus(AuthStatus authStatus) {
		this.authStatus = authStatus;
	}

	public Exception getException() {
		return exception;
	}

	public void setException(Exception exception) {
		this.exception = exception;
	}
	
	public boolean isFailed() {
		return authStatus == FAILURE;
	}
	
	public void add(AuthResult authResult) {
		if (!authResult.isFailed()) {
			authStatus = authResult.getAuthStatus();
		} else if (authResult.getException() != null) {
			if (exception != null) {
				exception = authResult.getException();
			} else {
				exception.addSuppressed(authResult.getException());
			}
		}
	}
	
	public AuthStatus throwOrReturnStatus() throws AuthException {
		maybeThrow();		
		return authStatus;
	}
	
	public AuthStatus throwOrFail() throws AuthException {
		maybeThrow();
		return FAILURE;
	}
	
	private void maybeThrow() throws AuthException {
		if (exception != null) {
			AuthException authException = new AuthException();
			authException.initCause(exception);
			throw authException;
		}
	}
	
}
