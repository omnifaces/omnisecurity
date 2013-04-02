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
package org.omnifaces.security.jaspic.factory;

import static java.util.Collections.unmodifiableList;
import static javax.security.auth.message.AuthStatus.SEND_CONTINUE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.jaspic.Jaspic.LOGGEDIN_ROLES;
import static org.omnifaces.security.jaspic.Jaspic.LOGGEDIN_USERNAME;
import static org.omnifaces.security.jaspic.Jaspic.isAuthenticationRequest;
import static org.omnifaces.security.jaspic.Jaspic.isExplicitAuthCall;
import static org.omnifaces.security.jaspic.Jaspic.isProtectedResource;
import static org.omnifaces.security.jaspic.Jaspic.isRegisterSession;
import static org.omnifaces.security.jaspic.Jaspic.notifyContainerAboutLogin;
import static org.omnifaces.security.jaspic.Utils.getBaseURL;
import static org.omnifaces.security.jaspic.Utils.redirect;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.ServerAuth;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.omnifaces.security.jaspic.AuthResult;
import org.omnifaces.security.jaspic.Jaspic;
import org.omnifaces.security.jaspic.config.Module;
import org.omnifaces.security.jaspic.request.RequestDataDAO;

/**
 * The Server Authentication Context is an extra (required) indirection between the Application Server and the actual Server Authentication Module
 * (SAM). This can be used to encapsulate any number of SAMs and either select one at run-time, invoke them all in order, etc.
 * <p>
 * Since this simple example only has a single SAM, we delegate directly to that one. Note that this {@link ServerAuthContext} and the
 * {@link ServerAuthModule} (SAM) share a common base interface: {@link ServerAuth}.
 *
 */
public class OmniServerAuthContext implements ServerAuthContext {
	
	private static final String AUTHENTICATOR_SESSION_NAME = "org.omnifaces.security.jaspic.Authenticator";

	private Map<String, List<Module>> stacks;
	private CallbackHandler handler;
	
	private final RequestDataDAO requestDAO = new RequestDataDAO();

	public OmniServerAuthContext(CallbackHandler handler, Map<String, List<Module>> stacks) throws AuthException {
		
		this.stacks = stacks;
		this.handler = handler;
		
		for (List<Module> modules : stacks.values()) {
			for (Module module : modules) {
				module.getServerAuthModule().initialize(null, null, handler, Collections.<String, String> emptyMap());
			}
		}
	}

	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
		
		AuthStatus status = doValidateRequest(messageInfo, clientSubject, serviceSubject);
		Jaspic.setLastStatus((HttpServletRequest) messageInfo.getRequestMessage(), status);
		
		return status;
	}
	
	public AuthStatus doValidateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
	
		HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();
		HttpServletResponse response = (HttpServletResponse) messageInfo.getResponseMessage();
		
		// Check to see if we're already authenticated.
		//
		// With JASPIC 1.0MR1, the container doesn't remember authentication data between requests and we thus have to
		// re-authenticate before every request. It's important to skip this step if authentication is explicitly requested, otherwise
		// we risk re-authenticating instead of processing a new login request.
		//
		// With JASPIC 1.0MR2, the container takes care of this detail if so requested.
		if (!isAuthenticationRequest(request) && canReAuthenticate(request, clientSubject, handler)) {
			return SUCCESS;
		}
		
		if (!isExplicitAuthCall(request)) {
			
			// Check to see if this request is to a protected resource
			//
			// We'll save the current request here, so we can redirect to the original URL after
			// authentication succeeds and when we start processing that URL wrap the request
			// with one containing the original headers, cookies, etc.
			if (isProtectedResource(messageInfo)) {
				
				requestDAO.save(request);
				redirect(response, getBaseURL(request) + "/login.xhtml");
							
				return SEND_CONTINUE; // End request processing for this request and don't try to process the handler
			}

			// No login request and no protected resource. Just continue.
			return SUCCESS;
		}
		
		boolean requiredFailed = false;
		AuthResult finalAuthResult = new AuthResult();
		
		try {
			for (Module module : stacks.values().iterator().next()) { // tmp
				
				AuthResult authResult = Jaspic.validateRequest(module.getServerAuthModule(), messageInfo, clientSubject, serviceSubject);
				finalAuthResult.add(authResult);
				
				switch (module.getControlFlag()) {
					
					case REQUIRED:
						if (authResult.isFailed()) {
							requiredFailed = true;
						}
						break;
						
					case REQUISITE:
						if (authResult.isFailed()) {
							return finalAuthResult.throwOrFail();
						}
						break;
						
					case SUFFICIENT:
						if (!authResult.isFailed() && !requiredFailed) {
							return authResult.getAuthStatus();
						}
						break;
				}
			}
			
			return finalAuthResult.throwOrReturnStatus();
			
		} finally {
			if (!finalAuthResult.isFailed() && isRegisterSession(messageInfo)) {
				saveAuthentication(request);
			}
		}
	}

	@Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
		
		AuthStatus authStatus = null;
		for (Module module : stacks.values().iterator().next()) { // tmp
			authStatus = module.getServerAuthModule().secureResponse(messageInfo, serviceSubject);
		}
		
		return authStatus;
	}

	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		for (Module module : stacks.values().iterator().next()) { // tmp
			module.getServerAuthModule().cleanSubject(messageInfo, subject);
		}
	}
	
	@SuppressWarnings("unchecked")
	private void saveAuthentication(HttpServletRequest request) {
		request.getSession().setAttribute(
			AUTHENTICATOR_SESSION_NAME, 
			new AuthenticationData(
				(String) request.getAttribute(LOGGEDIN_USERNAME),
				(List<String>) request.getAttribute(LOGGEDIN_ROLES)		
			)
		);
	}
	
	private boolean canReAuthenticate(HttpServletRequest request, Subject clientSubject, CallbackHandler handler) {
		
		HttpSession session = request.getSession(false);
		if (session != null) {
			AuthenticationData authenticationData = (AuthenticationData) session.getAttribute(AUTHENTICATOR_SESSION_NAME);
			if (authenticationData != null) {
				notifyContainerAboutLogin(clientSubject, handler, authenticationData.getUserName(), authenticationData.getApplicationRoles());
				
				return true;
			}
		}
		
		return false;
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