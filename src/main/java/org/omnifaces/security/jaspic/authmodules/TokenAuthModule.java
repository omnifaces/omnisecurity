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
package org.omnifaces.security.jaspic.authmodules;

import static java.util.regex.Pattern.compile;
import static org.omnifaces.security.cdi.Beans.getReferenceOrNull;
import static org.omnifaces.security.jaspic.Utils.isEmpty;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.omnifaces.security.jaspic.core.HttpMsgContext;
import org.omnifaces.security.jaspic.core.HttpServerAuthModule;
import org.omnifaces.security.jaspic.user.TokenAuthenticator;

/**
 * Authentication module that authenticates based on a token in the request.
 * 
 * <p>
 * Token to username/roles mapping is delegated to an implementation of {@link TokenAuthenticator}, which
 * should be registered as CDI bean.
 * 
 * <p>
 * <b>NOTE:</b> This module makes the simplifying assumption that CDI is available in a SAM. Unfortunately
 * this is not true for every implementation. See https://java.net/jira/browse/JASPIC_SPEC-14
 * 
 * @author Arjan Tijms
 *
 */
public class TokenAuthModule extends HttpServerAuthModule {
	
	private final static Pattern tokenPattern = compile("OmniLogin\\s+auth\\s*=\\s*(.*)");
	
	@Override
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws AuthException {
		
		String token = getToken(request);
		if (!isEmpty(token)) {
			
			// If a token is present, authenticate with it whether this is strictly required or not.
			
			TokenAuthenticator tokenAuthenticator = getReferenceOrNull(TokenAuthenticator.class);
			if (tokenAuthenticator != null) {
				
				if (tokenAuthenticator.authenticate(token)) {
					return httpMsgContext.notifyContainerAboutLogin(tokenAuthenticator.getUserName(), tokenAuthenticator.getApplicationRoles());
				}				
			}			
		}
		
		if (httpMsgContext.isProtected()) {
			return httpMsgContext.responseNotFound();
		}
		
		return httpMsgContext.doNothing();
	}
	
	private String getToken(HttpServletRequest request) {
		
		String authorizationHeader = request.getHeader("Authorization");
		if (!isEmpty(authorizationHeader)) {
			
			Matcher tokenMatcher = tokenPattern.matcher(authorizationHeader);
			
			if (tokenMatcher.matches()) {
				return tokenMatcher.group(1);
			}
		}
		
		return null;
	}

}