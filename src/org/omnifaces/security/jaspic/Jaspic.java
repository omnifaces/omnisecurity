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
import static org.omnifaces.util.Utils.isEmpty;
import static org.omnifaces.util.Utils.isOneOf;

import java.io.IOException;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.message.AuthStatus;
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
	
	public static final String IS_AUTHENTICATION = "org.omnifaces.security.message.request.authentication";
	public static final String IS_AUTHENTICATION_FROM_FILTER = "org.omnifaces.security.message.request.authenticationFromFilter";
	public static final String IS_SECURE_RESPONSE = "org.omnifaces.security.message.request.secureResponse";
	public static final String IS_LOGOUT = "org.omnifaces.security.message.request.isLogout";
	
	public static final String LOGGEDIN_USERNAME = "org.omnifaces.security.message.loggedin.username";
	public static final String LOGGEDIN_ROLES = "org.omnifaces.security.message.loggedin.roles";
	public static final String LAST_AUTH_STATUS = "org.omnifaces.security.message.authStatus";
	
	// Key in the MessageInfo Map that when present AND set to true indicated a protected resource is being accessed.
	// When the resource is not protected, GlassFish omits the key altogether. WebSphere does insert the key and sets
	// it to false.
	private static final String IS_MANDATORY = "javax.security.auth.message.MessagePolicy.isMandatory";
	private static final String REGISTER_SESSION = "javax.servlet.http.registerSession";

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
			request.setAttribute(IS_AUTHENTICATION, true);
			return request.authenticate(response);
		} catch (ServletException | IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			request.removeAttribute(IS_AUTHENTICATION);
		}
	}
	
	public static boolean authenticateFromFilter(HttpServletRequest request, HttpServletResponse response) {
		try {
			request.setAttribute(IS_AUTHENTICATION_FROM_FILTER, true);
			return request.authenticate(response);
		} catch (ServletException | IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			request.removeAttribute(IS_AUTHENTICATION_FROM_FILTER);
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
			request.setAttribute(IS_LOGOUT, true);
			request.authenticate(response);
		} catch (ServletException | IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			request.removeAttribute(IS_LOGOUT);
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
	
	public static void cleanSubject(Subject subject) {
	    if (subject != null) {
            subject.getPrincipals().clear();
        }
	}
	
	public static boolean isRegisterSession(MessageInfo messageInfo) {
		return Boolean.valueOf((String)messageInfo.getMap().get(REGISTER_SESSION));
	}
	
	public static boolean isProtectedResource(MessageInfo messageInfo) {
		return Boolean.valueOf((String) messageInfo.getMap().get(IS_MANDATORY));
	}
	
	@SuppressWarnings("unchecked")
	public static void setRegisterSession(MessageInfo messageInfo, String userName, List<String> roles) {
		messageInfo.getMap().put("javax.servlet.http.registerSession", TRUE.toString());
		
		HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
		request.setAttribute(LOGGEDIN_USERNAME, userName);
		// TODO: check for existing roles and add
		request.setAttribute(LOGGEDIN_ROLES, roles);
	}
	
	public static boolean isAuthenticationRequest(HttpServletRequest request) {
		return TRUE.equals(request.getAttribute(IS_AUTHENTICATION));
	}
	
	public static boolean isAuthenticationFromFilterRequest(HttpServletRequest request) {
		return TRUE.equals(request.getAttribute(IS_AUTHENTICATION_FROM_FILTER));
	}
	
	public static boolean isSecureResponseRequest(HttpServletRequest request) {
		return TRUE.equals(request.getAttribute(IS_SECURE_RESPONSE));
	}
	
	public static boolean isLogoutRequest(HttpServletRequest request) {
		return TRUE.equals(request.getAttribute(IS_LOGOUT));
	}
	
	/**
	 * Returns true if authorization was explicitly called for via this class (e.g. by calling {@link Jaspic#authenticate()},
	 * false if authorization was called automatically by the runtime at the start of the request or directly via e.g. 
	 * {@link HttpServletRequest#authenticate(HttpServletResponse)}
	 * 
	 * @param request
	 * @return true if authorization was initiated via this class, false otherwise
	 */
	public static boolean isExplicitAuthCall(HttpServletRequest request) {
		return isOneOf(TRUE, 
			request.getAttribute(IS_AUTHENTICATION), 
			request.getAttribute(IS_AUTHENTICATION_FROM_FILTER), 
			request.getAttribute(IS_SECURE_RESPONSE),
			request.getAttribute(IS_LOGOUT)
		);
	}
	
	public static void notifyContainerAboutLogin(Subject clientSubject, CallbackHandler handler, String userName, List<String> roles) {
		
	    try {
    		// 1. Create a handler (kind of directive) to add the caller principal (AKA user principal =basically user name, or user id) that
    		// the authenticator provides.
    		//
    		// This will be the name of the principal returned by e.g. HttpServletRequest#getUserPrincipal
	        // 
	        // 2 Execute the handler right away
            //
            // This will typically eventually (NOT right away) add the provided principal in an application server specific way to the JAAS 
	        // Subject.
            // (it could become entries in a hash table inside the subject, or individual principles, or nested group principles etc.)
    		
	        handler.handle(new Callback[] { new CallerPrincipalCallback(clientSubject, userName) });
    		
    		if (!isEmpty(roles)) {
        		// 1. Create a handler to add the groups (AKA roles) that the authenticator provides. 
        		//
        		// This is what e.g. HttpServletRequest#isUserInRole and @RolesAllowed for
        		//
        		// 2. Execute the handler right away
                //
                // This will typically eventually (NOT right away) add the provided roles in an application server specific way to the JAAS 
    	        // Subject.
                // (it could become entries in a hash table inside the subject, or individual principles, or nested group principles etc.)
		
    		    handler.handle(new Callback[] { new GroupPrincipalCallback(clientSubject, roles.toArray(new String[roles.size()])) });
    		}
			
		} catch (IOException | UnsupportedCallbackException e) {
			// Should not happen
			throw new IllegalStateException(e);
		}
	}
	
	public static void setLastStatus(HttpServletRequest request, AuthStatus status) {
		request.setAttribute(LAST_AUTH_STATUS, status);
	}
	
	public static AuthStatus getLastStatus(HttpServletRequest request) {
		return (AuthStatus) request.getAttribute(LAST_AUTH_STATUS);
	}
	
}
