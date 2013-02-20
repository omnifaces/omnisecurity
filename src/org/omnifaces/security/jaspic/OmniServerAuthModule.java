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
import static java.util.Collections.unmodifiableList;
import static javax.security.auth.message.AuthStatus.SEND_CONTINUE;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.cdi.Beans.getReference;
import static org.omnifaces.security.jaspic.OmniServerAuthModule.LoginResult.LOGIN_FAILURE;
import static org.omnifaces.security.jaspic.OmniServerAuthModule.LoginResult.LOGIN_SUCCESS;
import static org.omnifaces.security.jaspic.OmniServerAuthModule.LoginResult.NO_LOGIN;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.enterprise.inject.spi.BeanManager;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthStatus;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.omnifaces.security.cdi.Beans;
import org.omnifaces.security.jaspic.request.LoginTokenCookieDAO;
import org.omnifaces.security.jaspic.request.HttpServletRequestDelegator;
import org.omnifaces.security.jaspic.request.RequestDataDAO;
import org.omnifaces.security.jaspic.request.RequestData;
import org.omnifaces.security.jaspic.user.Authenticator;
import org.omnifaces.security.jaspic.user.TokenAuthenticator;
import org.omnifaces.security.jaspic.user.UsernamePasswordAuthenticator;


/**
 * The actual Server Authentication Module AKA SAM.
 *
 */
public class OmniServerAuthModule extends HttpServerAuthModule {
	
	private static final String AUTHENTICATOR_SESSION_NAME = "org.omnifaces.security.jaspic.Authenticator";
	
	private final RequestDataDAO requestDAO = new RequestDataDAO();
	private final LoginTokenCookieDAO cookieDAO = new LoginTokenCookieDAO();
	
	static enum LoginResult {
		LOGIN_SUCCESS,
		LOGIN_FAILURE,
		NO_LOGIN
	}
	
	@Override
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, Subject clientSubject, CallbackHandler handler, boolean isProtectedResource) {
				
		// Check to see if we're already authenticated.
		//
		// With JASPIC, the container doesn't remember authentication data between requests and we have thus have to
		// re-authenticate before every request. It's important to skip this step if authentication is explicitly requested, otherwise
		// we risk re-authenticating instead of processing a new login request.
		if (!isAuthenticationRequest(request) && canReAuthenticate(request, clientSubject, handler)) {
			return SUCCESS;
		}
		
		
			
		// Check to see if this is a request from user code to login
		//
		// In the case of this SAM, it means a managed bean or the filter method of this class has called request#authenticate (via Jaspic#authenticate)
		switch (isLoginRequest(request, response, clientSubject, handler)) {
		
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
		
		
		
		// Check to see if this request is to a protected resource
		//
		// We'll save the current request here, so we can redirect to the original URL after
		// authentication succeeds and when we start processing that URL wrap the request
		// with one containing the original headers, cookies, etc.
		if (isProtectedResource) {
			
			requestDAO.save(request);
			redirect(response, getBaseURL(request) + "/login.xhtml");
						
			return SEND_CONTINUE; // End request processing for this request and don't try to process the handler
		}

		// Not already authenticated, no login request and no protected resource. Just continue.
		return SUCCESS;
	}
	
	/**
	 * When access to the request resource is granted, this method will be invoked after validateHttpRequest.
	 * <p>
	 * The reason for this extra method is that in this method CDI and EJB are available, while in validateHttpRequest this is
	 * for most servers not the case.
	 * <p>
	 * Additionally, in this method we can wrap the request if needed. This should be possible in validateHttpRequest as well, but
	 * in practice no known JASPIC implementation actually supports this.
	 * 
	 */
	@Override
	public void doFilterHttp(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain) throws IOException, ServletException {
				
		// See if there was a saved request that matches the current request and restore
		// that request by wrapping the current request.
		//
		// Note that it doesn't seem possible to do this in a portable way in validateHttpRequest
		RequestData requestData = requestDAO.get(request);
		Cookie cookie = cookieDAO.get(request);
		HttpServletRequest newRequest = request;
		
		if (requestData != null) {
			
			if (requestData.matchesRequest(request)) {
				newRequest = new HttpServletRequestDelegator(request, requestData);
				requestDAO.remove(request);
			} else if (cookie != null && request.getRequestURL().toString().equals(getBaseURL(request) + "/login.xhtml")) {
				// There is requestData available and a cookie, as well as a request to the login page.
				// We use this login page as a cue to do login via the cookie.
				if (Jaspic.authenticate(request, response)) {
					// If authentication succeeded, don't process the request to the login page.
					return;
				}
			}
		}
		
		chain.doFilter(newRequest, response);
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
	
	private boolean canReAuthenticate(HttpServletRequest request, Subject clientSubject, CallbackHandler handler) {
		
		HttpSession session = request.getSession(false);
		if (session != null) {
			AuthenticationData authenticationData = (AuthenticationData) session.getAttribute(AUTHENTICATOR_SESSION_NAME);
			if (authenticationData != null) {
				notifyContainerAboutLogin(request, clientSubject, handler, authenticationData.getUserName(), authenticationData.getApplicationRoles());
				
				return true;
			}
		}
		
		return false;
	}
	
	private LoginResult isLoginRequest(HttpServletRequest request, HttpServletResponse response, Subject clientSubject, CallbackHandler handler) {
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
				
				notifyContainerAboutLogin(request, clientSubject, handler, authenticator.getUserName(), authenticator.getApplicationRoles());
				
				// Since CDI is not universally available when this SAM is called at the beginning of a request, we
				// explicitly store our authenticator bean in the HTTP session, so we can later on (the next requests) retrieve it
				// to re-authenticate.
				request.getSession().setAttribute(
					AUTHENTICATOR_SESSION_NAME, 
					new AuthenticationData(authenticator.getUserName(), authenticator.getApplicationRoles())
				);
				
				if (tokenAuthenticator != null && TRUE.equals(request.getAttribute(REMEMBERME_KEY))) {
					cookieDAO.save(request, response, tokenAuthenticator.generateLoginToken());
				} else if (cookie != null) {
					// New login, but user doesn't want "remember me" anymore. Remove existing cookie if it happens
					// to be still present. 
					cookieDAO.remove(request, response);
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
	
	private class AuthenticationData {

		private final String userName;
		private final List<String> applicationRoles;

		public AuthenticationData(String userName, List<String> applicationRoles) {
			this.userName = userName;
			this.applicationRoles = unmodifiableList(new ArrayList<>(applicationRoles));
		}

		public String getUserName() {
			return userName;
		}

		public List<String> getApplicationRoles() {
			return applicationRoles;
		}
	}

	
}