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
import static javax.security.auth.message.AuthStatus.FAILURE;
import static javax.security.auth.message.AuthStatus.SEND_SUCCESS;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.util.Utils.coalesce;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A server authentication module (SAM) implementation base class, tailored for the Servlet Container Profile.
 * 
 * @author Arjan Tijms
 * 
 */
public abstract class HttpServerAuthModule implements ServerAuthModule, Filter {
	
	public static final String IS_LOGOUT_KEY = "org.omnifaces.security.message.request.isLogout";
	public static final String IS_AUTHENTICATION_KEY = "org.omnifaces.security.message.request.isAuthentication";
	public static final String USERNAME_KEY = "org.omnifaces.security.message.request.username";
	public static final String PASSWORD_KEY = "org.omnifaces.security.message.request.password";
	public static final String REMEMBERME_KEY = "org.omnifaces.security.message.request.rememberme";
	
	// Key in the MessageInfo Map that when present AND set to true indicated a protected resource is being accessed.
	// When the resource is not protected, GlassFish omits the key altogether. WebSphere does insert the key and sets
	// it to false.
	private static final String IS_MANDATORY_KEY = "javax.security.auth.message.MessagePolicy.isMandatory";

	private CallbackHandler handler;
	private final Class<?>[] supportedMessageTypes = new Class[] { HttpServletRequest.class, HttpServletResponse.class };

	@Override
	public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
			@SuppressWarnings("rawtypes") Map options) throws AuthException {
		this.handler = handler;
	}
	
	@Override
	public void init(FilterConfig config) throws ServletException {
		
	}

	/**
	 * A Servlet Container Profile compliant implementation should return HttpServletRequest and HttpServletResponse, so
	 * the delegation class {@link ServerAuthContext} can choose the right SAM to delegate to.
	 */
	@Override
	public Class<?>[] getSupportedMessageTypes() {
		return supportedMessageTypes;
	}
	
	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
		
		// Cast the request and response messages. Because of our getSupportedMessageTypes, they have to be of the correct
		// types and casting should always work.
		HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
		HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
		boolean isProtectedResource = Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY_KEY));
		
		AuthStatus status = null;
		if (request.getAttribute(IS_LOGOUT_KEY) != null) {
			status = logout(request, response, clientSubject);
		} else {
			status = validateHttpRequest(request, response, clientSubject, handler, isProtectedResource);
		}
		
		if (status == FAILURE) {
			throw new IllegalStateException("Servlet Container Profile SAM should not return status FAILURE. This is for CLIENT SAMs only");
		}
		
		return status;
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		doFilterHttp((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}
	
	public void doFilterHttp(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
		
	}
	
	/**
	 * WebLogic 12c and JBoss EAP 6 (optionally) calls this before Servlet is called, Geronimo v3 and GlassFish 3.1.2.2 after. WebLogic
	 * (seemingly) only continues if SEND_SUCCESS is returned, Geronimo completely ignores return value.
	 */
	@Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
		return SEND_SUCCESS;
	}

	/**
	 * Doesn't seem to be called by any server, ever.
	 */
	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		if (subject != null) {
			subject.getPrincipals().clear();
		}
	}
	
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject, CallbackHandler handler, boolean isProtectedResource) {
		return validateHttpRequest(request, response, clientSubject, handler, isProtectedResource);
	}
	
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, Subject clientSubject, CallbackHandler handler, boolean isProtectedResource) {
		throw new IllegalStateException("Not implemented");
	}
	
	public AuthStatus logout(HttpServletRequest request, HttpServletResponse response, Subject clientSubject) {
		return SUCCESS;
	}
	
	@Override
	public void destroy() {
		
	}
	
	public boolean isAuthenticationRequest(HttpServletRequest request) {
		return TRUE.equals(request.getAttribute(IS_AUTHENTICATION_KEY));
	}
	
	public void notifyContainerAboutLogin(HttpServletRequest request, Subject clientSubject, CallbackHandler handler, String userName, List<String> roles) {
		
		// Create a handler (kind of directive) to add the caller principal (AKA user principal =basically user name, or user id) that
		// the authenticator provides.
		//
		// This will be the name of the principal returned by e.g. HttpServletRequest#getUserPrincipal
		CallerPrincipalCallback callerPrincipalCallback = new CallerPrincipalCallback(clientSubject, userName);
		
		// Create a handler to add the groups (AKA roles) that the authenticator provides. 
		//
		// This is what e.g. HttpServletRequest#isUserInRole and @RolesAllowed for
		GroupPrincipalCallback groupPrincipalCallback = new GroupPrincipalCallback(clientSubject, roles.toArray(new String[roles.size()]));

		
		try {
			// Execute the handlers we created above. 
			//
			// This will typically add the provided principal and roles in an application server specific way to the JAAS Subject.
			// (it could become entries in a hash table inside the subject, or individual principles, or nested group principles etc.
			handler.handle(new Callback[] { callerPrincipalCallback, groupPrincipalCallback });
			
		} catch (IOException | UnsupportedCallbackException e) {
			// Should not happen
			throw new IllegalStateException(e);
		}
	}
	
	
	public boolean notNull(Object... objects) {
		return coalesce(objects) != null;
	}
	
	public String getBaseURL(HttpServletRequest request) {
		String url = request.getRequestURL().toString();
		return url.substring(0, url.length() - request.getRequestURI().length()) + request.getContextPath();
	}
	
	public void redirect(HttpServletResponse response, String location) {
		try {
			response.sendRedirect(location);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

}
