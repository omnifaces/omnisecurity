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

import static javax.security.auth.message.AuthStatus.SEND_CONTINUE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.jaspic.Utils.getBaseURL;
import static org.omnifaces.security.jaspic.Utils.redirect;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.module.ServerAuthModule;

import org.omnifaces.security.jaspic.core.AuthParameters;
import org.omnifaces.security.jaspic.core.HttpMsgContext;
import org.omnifaces.security.jaspic.core.ServerAuthModuleWrapper;
import org.omnifaces.security.jaspic.request.RequestDataDAO;

public class SaveAndRedirectWrapper extends ServerAuthModuleWrapper {
	
	public static final String PUBLIC_REDIRECT_URL = "publicRedirectUrl";
	
	private CallbackHandler handler;
	private Map<String, String> options;
	
	private final RequestDataDAO requestDAO = new RequestDataDAO();
	
	public SaveAndRedirectWrapper(ServerAuthModule serverAuthModule) {
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
		
		if (!msgContext.isAnyExplicitAuthCall()) {

            // Check to see if this request is to a protected resource
            //
            // We'll save the current request here, so we can redirect to the original URL after
            // authentication succeeds and when we start processing that URL wrap the request
            // with one containing the original headers, cookies, etc.
            if (msgContext.isProtected()) {

                requestDAO.save(msgContext.getRequest());
                redirect(msgContext.getResponse(), getBaseURL(msgContext.getRequest()) + msgContext.getModuleOption(PUBLIC_REDIRECT_URL) + "?new=false");

                return SEND_CONTINUE; // End request processing for this request and don't try to process the handler
            }

            // No explicit login request and no protected resource. Just continue.
            return SUCCESS;
        } else {
        	
        	// An explicit authentication call was done. Check if this call was accompanied by a
        	// redirect URL
        	
        	String redirectUrl = getRedirectUrl(msgContext);
        	if (redirectUrl != null) {
    			requestDAO.saveUrlOnly(msgContext.getRequest(), redirectUrl);
    		}
        	
        	return super.validateRequest(messageInfo, clientSubject, serviceSubject);
        }
	}
	
	private String getRedirectUrl(HttpMsgContext msgContext) {
		AuthParameters authParameters = msgContext.getAuthParameters();
		return authParameters != null ? authParameters.getRedirectUrl() : null;
	}

}