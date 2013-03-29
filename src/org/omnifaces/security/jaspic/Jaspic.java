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
import static org.omnifaces.security.jaspic.HttpServerAuthModule.IS_LOGOUT_KEY;

import java.io.IOException;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.omnifaces.util.Faces;

/**
 * A set of utility methods for using the JASPIC API, specially in combination with
 * the OmniServerAuthModule.
 * <p>
 * Note that this contains various methods that assume being called from a JSF context.
 * 
 * @author Arjan Tijms
 *
 */
public final class Jaspic {
	
	public static final String IS_AUTHENTICATION_KEY = "org.omnifaces.security.message.request.isAuthentication";
	public static final String LOGGEDIN_USERNAME_KEY = "org.omnifaces.security.message.loggedin.username";
	public static final String LOGGEDIN_ROLES_KEY = "org.omnifaces.security.message.loggedin.roles";

	private Jaspic() {}
		
	public static boolean authenticate() {
		return authenticate(Faces.getRequest(), Faces.getResponse());
	}
	
	public static boolean authenticate(String username, String password, boolean rememberMe) {
		
		HttpServletRequest request = Faces.getRequest();
		
		try {
			request.setAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.USERNAME_KEY , username);
			request.setAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.PASSWORD_KEY , password);
			request.setAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.REMEMBERME_KEY , rememberMe);
		return authenticate(request, Faces.getResponse());
		} finally {
			request.removeAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.USERNAME_KEY);
			request.removeAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.PASSWORD_KEY);
			request.removeAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.REMEMBERME_KEY);
		}
	}
	
	public static boolean authenticate(HttpServletRequest request, HttpServletResponse response) {
		try {
			request.setAttribute(IS_AUTHENTICATION_KEY, true);
			return request.authenticate(response);
		} catch (ServletException | IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			request.removeAttribute(IS_AUTHENTICATION_KEY);
		}
	}
	
	public static void logout() {
		logout(Faces.getRequest(), Faces.getResponse());
	}
	
	public static void logout(HttpServletRequest request, HttpServletResponse response) {
		try {
			request.getSession().invalidate();
			request.logout();
			
			// Hack to signal to the SAM that we are logging out. Only works this way
			// for the OmniServerAuthModule.
			request.setAttribute(IS_LOGOUT_KEY, true);
			request.authenticate(response);
		} catch (ServletException | IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			request.removeAttribute(IS_LOGOUT_KEY);
		}
	}
	
	public static AuthResult validateRequest(ServerAuthModule serverAuthModule,	MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) {
		
		AuthResult authResult = new AuthResult();
		
		try {
			authResult.setAuthStatus(serverAuthModule.validateRequest(messageInfo, clientSubject, serviceSubject));
		} catch (Exception exception) {
			authResult.setException(exception);
		}
		
		return authResult;
	}
	
	public static boolean isRegisterSession(MessageInfo messageInfo) {
		return Boolean.valueOf((String)messageInfo.getMap().get("javax.servlet.http.registerSession"));
	}
	
	@SuppressWarnings("unchecked")
	public static void setRegisterSession(MessageInfo messageInfo, String userName, List<String> roles) {
		messageInfo.getMap().put("javax.servlet.http.registerSession", TRUE.toString());
		
		HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
		request.setAttribute(LOGGEDIN_USERNAME_KEY, userName);
		// TODO: check for existing roles and add
		request.setAttribute(LOGGEDIN_ROLES_KEY, roles);
	}
	
	public static boolean isAuthenticationRequest(HttpServletRequest request) {
		return TRUE.equals(request.getAttribute(IS_AUTHENTICATION_KEY));
	}
	
	public static void notifyContainerAboutLogin(Subject clientSubject, CallbackHandler handler, String userName, List<String> roles) {
		
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
	
	
}
