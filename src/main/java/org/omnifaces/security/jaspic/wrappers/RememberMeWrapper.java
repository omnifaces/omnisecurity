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

import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.cdi.Beans.getReferenceOrNull;
import static org.omnifaces.security.jaspic.Utils.getSingleParameterFromState;
import static org.omnifaces.security.jaspic.Utils.notNull;
import static org.omnifaces.security.jaspic.factory.OmniServerAuthContext.REMEMBER_ME_SESSION_NAME;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpSession;

import org.omnifaces.security.jaspic.core.HttpMsgContext;
import org.omnifaces.security.jaspic.core.ServerAuthModuleWrapper;
import org.omnifaces.security.jaspic.request.LoginTokenCookieDAO;
import org.omnifaces.security.jaspic.user.TokenAuthenticator;

public class RememberMeWrapper extends ServerAuthModuleWrapper {
	
	private final LoginTokenCookieDAO cookieDAO = new LoginTokenCookieDAO();
	
	private CallbackHandler handler;
	private Map<String, String> options;
	
	public RememberMeWrapper(ServerAuthModule serverAuthModule) {
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
		TokenAuthenticator tokenAuthenticator =	getReferenceOrNull(TokenAuthenticator.class);
		Cookie cookie = cookieDAO.get(msgContext.getRequest());
		
		// First try to see if we can authenticate via a cookie
		if (notNull(tokenAuthenticator, cookie)) {
			if (tokenAuthenticator.authenticate(cookie.getValue())) {
				
				// We were able to authenticate via the remember-me cookie, register this with the container and return
				msgContext.registerWithContainer(tokenAuthenticator.getUserName(), tokenAuthenticator.getApplicationRoles());
				
				return null; // SUCCESS && abort chain
			} else {
				// Invalid cookie, remove it
				cookieDAO.remove(msgContext.getRequest(), msgContext.getResponse());
			}
		}
				
		// Let the next wrapper of SAM try to authenticate		
		AuthStatus authstatus = super.validateRequest(messageInfo, clientSubject, serviceSubject);

		if (tokenAuthenticator != null && authstatus == SUCCESS && isRememberMe(msgContext)) {
			cookieDAO.save(msgContext.getRequest(), msgContext.getResponse(), tokenAuthenticator.generateLoginToken());
		}

		return authstatus;
	}
	
	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		
		HttpMsgContext msgContext = new HttpMsgContext(handler, options, messageInfo, subject);
		
		// If there's a "remember me" cookie present, remove it.
		Cookie cookie = cookieDAO.get(msgContext.getRequest());
		
		if (cookie != null) {
			cookieDAO.remove(msgContext.getRequest(), msgContext.getResponse());
			
			TokenAuthenticator tokenAuthenticator =	getReferenceOrNull(TokenAuthenticator.class);
						
			if (tokenAuthenticator != null) {
				tokenAuthenticator.removeLoginToken(cookie.getValue());
			}				
		}
		
		super.cleanSubject(messageInfo, subject);
	}
	
	public boolean isRememberMe(HttpMsgContext msgContext) {
		
		// TODO: handle state better
		
		if (msgContext.getAuthParameters().getRememberMe() != null) {
			return msgContext.getAuthParameters().getRememberMe();
		}
		
		if (msgContext.getRequest().getParameter("state") != null) {
			String rememberMe = getSingleParameterFromState(msgContext.getRequest().getParameter("state"), "rememberMe");
			if (rememberMe != null) {
				return Boolean.valueOf(rememberMe);
			}
		}
		
		HttpSession session = msgContext.getRequest().getSession(false);
		if (session != null) {
			Boolean rememberMe = (Boolean) session.getAttribute(REMEMBER_ME_SESSION_NAME);
			if (rememberMe != null) {
				return rememberMe;
			}
		}
		
		return false;		
	}
	
}