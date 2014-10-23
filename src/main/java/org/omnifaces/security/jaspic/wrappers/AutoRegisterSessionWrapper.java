/*
 * Copyright 2014 OmniFaces.
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
package org.omnifaces.security.jaspic.wrappers;

import static java.util.Collections.unmodifiableList;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.jaspic.core.Jaspic.LOGGEDIN_ROLES;
import static org.omnifaces.security.jaspic.core.Jaspic.LOGGEDIN_USERNAME;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.omnifaces.security.jaspic.core.HttpMsgContext;
import org.omnifaces.security.jaspic.core.ServerAuthModuleWrapper;

public class AutoRegisterSessionWrapper extends ServerAuthModuleWrapper {
	
	private static final String AUTHENTICATOR_SESSION_NAME = "org.omnifaces.security.jaspic.Authenticator";
	
	private CallbackHandler handler;
	private Map<String, String> options;
	
	public AutoRegisterSessionWrapper(ServerAuthModule serverAuthModule) {
		super(serverAuthModule);
	}
	
	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options)	throws AuthException {
		super.initialize(requestPolicy, responsePolicy, handler, options);
		this.handler = handler;
		this.options = options;
	}
	
	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {

		HttpMsgContext msgContext = new HttpMsgContext(handler, options, messageInfo, clientSubject);
		
		// Check to see if we're already authenticated.
        //
        // With JASPIC 1.0MR1, the container doesn't remember authentication data between requests and we thus have to
        // re-authenticate before every request. It's important to skip this step if authentication is explicitly requested, otherwise
        // we risk re-authenticating instead of processing a new login request.
        //
        // With JASPIC 1.1, the container partially takes care of this detail if so requested.
        if (!msgContext.isAuthenticationRequest() && canReAuthenticate(msgContext)) {
            return SUCCESS;
        }
		
        AuthStatus authstatus = super.validateRequest(messageInfo, clientSubject, serviceSubject);
        if (authstatus == AuthStatus.SUCCESS) {
        	saveAuthentication(msgContext.getRequest());
        }
        
        return authstatus;        
	}
	
	private boolean canReAuthenticate(HttpMsgContext msgContext) {
		AuthenticationData authenticationData = getAuthenticationDataFromSession(msgContext);
		if (authenticationData != null) {
			msgContext.notifyContainerAboutLogin(authenticationData.getUserName(), authenticationData.getApplicationRoles());
			return true;
		}

		return false;
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
	
	private AuthenticationData getAuthenticationDataFromSession(HttpMsgContext msgContext) {
		HttpSession session = msgContext.getRequest().getSession(false);
		if (session != null) {
			return (AuthenticationData) session.getAttribute(AUTHENTICATOR_SESSION_NAME);
		}
		
		return null;			
	}
	
	private class AuthenticationData {

		private final String username;
		private final List<String> applicationRoles;

		public AuthenticationData(String username, List<String> applicationRoles) {
			this.username = username;
			this.applicationRoles = unmodifiableList(new ArrayList<>(applicationRoles));
		}

		public String getUserName() {
			return username;
		}

		public List<String> getApplicationRoles() {
			return applicationRoles;
		}
	}

}
