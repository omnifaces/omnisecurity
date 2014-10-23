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
package org.omnifaces.security.jaspic.core;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.module.ServerAuthModule;

public class ServerAuthModuleWrapper implements ServerAuthModule {

	private ServerAuthModule wrapped;
	
	public ServerAuthModuleWrapper(ServerAuthModule serverAuthModule) {
		this.wrapped = serverAuthModule;
	}
	
	@SuppressWarnings("rawtypes")
	@Override
	public Class[] getSupportedMessageTypes() {
		return wrapped.getSupportedMessageTypes();
	}
	
	@Override
	public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, @SuppressWarnings("rawtypes") Map options) throws AuthException {
		wrapped.initialize(requestPolicy, responsePolicy, handler, options);
	}
	
	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {
		return wrapped.validateRequest(messageInfo, clientSubject, serviceSubject);
	}
	
	@Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
		return wrapped.secureResponse(messageInfo, serviceSubject);
	}
	
	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		wrapped.cleanSubject(messageInfo, subject);
	}

}