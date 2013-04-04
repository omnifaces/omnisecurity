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

import static javax.security.auth.message.AuthStatus.SEND_SUCCESS;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A server authentication module (SAM) implementation base class, tailored for the Servlet Container Profile.
 *
 * @author Arjan Tijms
 *
 */
public abstract class HttpServerAuthModule implements ServerAuthModule {

	public static final String USERNAME_KEY = "org.omnifaces.security.message.request.username";
	public static final String PASSWORD_KEY = "org.omnifaces.security.message.request.password";
	public static final String REMEMBERME_KEY = "org.omnifaces.security.message.request.rememberme";

	private CallbackHandler handler;
	private final Class<?>[] supportedMessageTypes = new Class[] { HttpServletRequest.class, HttpServletResponse.class };

	@Override
	public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler,
			@SuppressWarnings("rawtypes") Map options) throws AuthException {
		this.handler = handler;
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
		HttpMsgContext msgContext = new HttpMsgContext(handler, messageInfo, clientSubject);
		return validateHttpRequest(msgContext.getRequest(), msgContext.getResponse(), msgContext);
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
	 * Called in response to a {@link HttpServletRequest#logout()} call.
	 *
	 */
	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
	    HttpMsgContext msgContext = new HttpMsgContext(handler, messageInfo, subject);
		cleanHttpSubject(msgContext.getRequest(), msgContext.getResponse(), msgContext);
	}

	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws AuthException {
		throw new IllegalStateException("Not implemented");
	}

	public void cleanHttpSubject(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) {
	    httpMsgContext.cleanClientSubject();
	}

}
