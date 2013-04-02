/*
 * Copyright 2013 OmniFaces.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.omnifaces.security.jaspic;

import static java.lang.Boolean.TRUE;
import static javax.security.auth.message.AuthStatus.SEND_CONTINUE;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.cdi.Beans.getReference;
import static org.omnifaces.security.jaspic.Jaspic.notifyContainerAboutLogin;
import static org.omnifaces.security.jaspic.Jaspic.setRegisterSession;
import static org.omnifaces.security.jaspic.OmniServerAuthModule.LoginResult.LOGIN_FAILURE;
import static org.omnifaces.security.jaspic.OmniServerAuthModule.LoginResult.LOGIN_SUCCESS;
import static org.omnifaces.security.jaspic.OmniServerAuthModule.LoginResult.NO_LOGIN;
import static org.omnifaces.security.jaspic.Utils.notNull;
import static org.omnifaces.security.jaspic.Utils.redirect;

import javax.enterprise.inject.spi.BeanManager;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.omnifaces.security.cdi.Beans;
import org.omnifaces.security.jaspic.request.LoginTokenCookieDAO;
import org.omnifaces.security.jaspic.request.RequestData;
import org.omnifaces.security.jaspic.request.RequestDataDAO;
import org.omnifaces.security.jaspic.user.Authenticator;
import org.omnifaces.security.jaspic.user.TokenAuthenticator;
import org.omnifaces.security.jaspic.user.UsernamePasswordAuthenticator;


/**
 * The actual Server Authentication Module AKA SAM.
 *
 */
public class OmniServerAuthModule extends HttpServerAuthModule {
	
	private final RequestDataDAO requestDAO = new RequestDataDAO();
	private final LoginTokenCookieDAO cookieDAO = new LoginTokenCookieDAO();
	
	static enum LoginResult {
		LOGIN_SUCCESS,
		LOGIN_FAILURE,
		NO_LOGIN
	}
	
	@Override
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject, CallbackHandler handler, boolean isProtectedResource) {
			
		// Check to see if this is a request from user code to login
		//
		// In the case of this SAM, it means a managed bean or the filter method of this class has called request#authenticate (via Jaspic#authenticate)
		switch (isLoginRequest(request, response, messageInfo, clientSubject, handler)) {
		
			case LOGIN_SUCCESS:
		
				// Check if there's a previously saved request. This is the case if a protected request was
				// accessed earlier and the user was subsequently redirected to the login page.
				RequestData requestData = requestDAO.get(request);
				if (requestData != null) {
					
					// We redirect the user to the original URL that was requested. The doFilter method below will
					// hit when this new URL is requested and uses RequestData to restore the headers, cookies etc
					// from the original request.
					redirect(response, requestData.getFullRequestURL());
				} 
				
				return SUCCESS;
				
			case LOGIN_FAILURE:
				
				// End request processing and don't try to process the handler
				//
				// Note: Most JASPIC implementations don't distinguish between return codes and only check if return is SUCCESS or not
				// Note: In the case of this SAM, login is called following a request#authenticate only, so in that case a non-SUCCESS
				//       return only means not to process the handler.
				return SEND_FAILURE; 
		}

		// No login request and no protected resource. Just continue.
		return SUCCESS;
	}
	
	@Override
	public AuthStatus logout(HttpServletRequest request, HttpServletResponse response, Subject clientSubject) {
		
		// If there's a "remember me" cookie present, remove it.
		if (cookieDAO.get(request) != null) {
			cookieDAO.remove(request, response);
			Delegators delegators = tryGetDelegators();
			if (delegators != null && delegators.getTokenAuthenticator() != null) {
				delegators.getTokenAuthenticator().removeLoginToken();			
			}				
		}
		
		return SEND_CONTINUE;
	}
	
	private LoginResult isLoginRequest(HttpServletRequest request, HttpServletResponse response, MessageInfo messageInfo, Subject clientSubject, CallbackHandler handler) {
		Delegators delegators = tryGetDelegators();
		
		// This SAM is supposed to work following a call to HttpServletRequest#authenticate. Such call is in-context of the component executing it,
		// which *should* have the correct CDI contexts active to obtain our CDI delegators.
		//
		// In case this SAM is triggered at the very beginning of a request (which is before even the first Servlet Filter kicks in), those CDI
		// contexts are typically not (fully) available.
		if (delegators != null) {
			
			UsernamePasswordAuthenticator usernamePasswordAuthenticator = delegators.getAuthenticator();
			TokenAuthenticator tokenAuthenticator =	delegators.getTokenAuthenticator();
			
			Cookie cookie = cookieDAO.get(request);
			
			Authenticator authenticator = null;
			boolean authenticated = false;
			if (notNull(request.getAttribute(USERNAME_KEY), request.getAttribute(PASSWORD_KEY))) {
				authenticated = usernamePasswordAuthenticator.authenticate(
					(String) request.getAttribute(USERNAME_KEY),
					(String) request.getAttribute(PASSWORD_KEY)
				);
				
				authenticator = usernamePasswordAuthenticator;
			} else if (cookie != null && tokenAuthenticator != null) {
				authenticated = tokenAuthenticator.authenticate(cookie.getValue());
				
				if (!authenticated) {
					// Invalid cookie, remove it
					cookieDAO.remove(request, response);
					
					// Authentication via cookie is an implicit login, so if it fails we just ignore it
					// so the flow falls-through to the normal login.
					return NO_LOGIN;
				} else {
					authenticator = tokenAuthenticator;
				}
			} else {
				return NO_LOGIN;
			}
			
			if (authenticated) {
				
				notifyContainerAboutLogin(clientSubject, handler, authenticator.getUserName(), authenticator.getApplicationRoles());
				
				// Ask the runtime to remember the authenticated details for the duration of the http session.
				setRegisterSession(messageInfo, authenticator.getUserName(), authenticator.getApplicationRoles());
				
				if (tokenAuthenticator != null && TRUE.equals(request.getAttribute(REMEMBERME_KEY))) {
					cookieDAO.save(request, response, tokenAuthenticator.generateLoginToken());
				}
				
				return LOGIN_SUCCESS;
			} else {
				return LOGIN_FAILURE;
			}
			
		}
		
		return NO_LOGIN;
	}
	
	private Delegators tryGetDelegators() {
		try {
			BeanManager beanManager = Beans.getBeanManager();

			return new Delegators(
				getReference(UsernamePasswordAuthenticator.class, beanManager),
				getReference(TokenAuthenticator.class, beanManager)
			);
		} catch (Exception e) {
			return null;
		}
	}
	
	private static class Delegators {

		private final UsernamePasswordAuthenticator authenticator;
		private final TokenAuthenticator tokenAuthenticator;

		public Delegators(UsernamePasswordAuthenticator authenticator, TokenAuthenticator tokenAuthenticator) {
			this.authenticator = authenticator;
			this.tokenAuthenticator = tokenAuthenticator;
		}

		public UsernamePasswordAuthenticator getAuthenticator() {
			return authenticator;
		}

		public TokenAuthenticator getTokenAuthenticator() {
			return tokenAuthenticator;
		}
	}
	
}