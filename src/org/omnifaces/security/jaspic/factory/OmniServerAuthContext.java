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

import java.util.Collections;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.ServerAuth;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;

import org.omnifaces.security.jaspic.OmniServerAuthModule;

/**
 * The Server Authentication Context is an extra (required) indirection between the Application Server and the actual Server Authentication Module
 * (SAM). This can be used to encapsulate any number of SAMs and either select one at run-time, invoke them all in order, etc.
 * <p>
 * Since this simple example only has a single SAM, we delegate directly to that one. Note that this {@link ServerAuthContext} and the
 * {@link ServerAuthModule} (SAM) share a common base interface: {@link ServerAuth}.
 *
 */
public class OmniServerAuthContext implements ServerAuthContext {

	private ServerAuthModule serverAuthModule;

	public OmniServerAuthContext(CallbackHandler handler) throws AuthException {
		serverAuthModule = new OmniServerAuthModule();
		serverAuthModule.initialize(null, null, handler, Collections.<String, String> emptyMap());
	}

	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
		return serverAuthModule.validateRequest(messageInfo, clientSubject, serviceSubject);
	}

	@Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
		return serverAuthModule.secureResponse(messageInfo, serviceSubject);
	}

	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		serverAuthModule.cleanSubject(messageInfo, subject);
	}

}