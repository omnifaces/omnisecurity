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
package org.omnifaces.security.jaspic.authmodules;

import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.cdi.Beans.getReferenceOrNull;
import static org.omnifaces.security.jaspic.Utils.notNull;
import static org.omnifaces.security.jaspic.authmodules.OmniServerAuthModule.LoginResult.LOGIN_FAILURE;
import static org.omnifaces.security.jaspic.authmodules.OmniServerAuthModule.LoginResult.LOGIN_SUCCESS;
import static org.omnifaces.security.jaspic.authmodules.OmniServerAuthModule.LoginResult.NO_LOGIN;
import static org.omnifaces.security.jaspic.core.ServiceType.AUTO_REGISTER_SESSION;
import static org.omnifaces.security.jaspic.core.ServiceType.REMEMBER_ME;
import static org.omnifaces.security.jaspic.core.ServiceType.SAVE_AND_REDIRECT;

import javax.enterprise.inject.spi.BeanManager;
import javax.security.auth.message.AuthStatus;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.omnifaces.security.cdi.Beans;
import org.omnifaces.security.jaspic.core.AuthParameters;
import org.omnifaces.security.jaspic.core.HttpMsgContext;
import org.omnifaces.security.jaspic.core.HttpServerAuthModule;
import org.omnifaces.security.jaspic.core.Jaspic;
import org.omnifaces.security.jaspic.core.SamServices;
import org.omnifaces.security.jaspic.user.Authenticator;
import org.omnifaces.security.jaspic.user.UsernameOnlyAuthenticator;
import org.omnifaces.security.jaspic.user.UsernamePasswordAuthenticator;


/**
 * The actual Server Authentication Module AKA SAM. This SAM is designed to work specifically with a user space
 * user name/password {@link Authenticator} that is obtained via a CDI bean manager lookup.
 * <p>
 * 
 * Authentication is triggered by the presence of request attributes {@link Jaspic#AUTH_PARAMS} with a non-null username and password
 * <p>
 * 
 * The intended usage of this SAM is via a regular JSF user name/password form backed by a bean that sets the above mentioned
 * request attributes and then calls {@link HttpServletRequest#authenticate(HttpServletResponse)}. This project provides
 * {@link Jaspic#authenticate()} as a convenience shortcut for that.
 *
 */
@SamServices({AUTO_REGISTER_SESSION, SAVE_AND_REDIRECT, REMEMBER_ME})
public class OmniServerAuthModule extends HttpServerAuthModule {
	
	static enum LoginResult {
		LOGIN_SUCCESS,
		LOGIN_FAILURE,
		NO_LOGIN
	}
	
	@Override
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) {
			
		// Check to see if this is a request from user code to login
		//
		// In the case of this SAM, it means a managed bean or the Filter method has called request#authenticate (via Jaspic#authenticate)
		switch (isLoginRequest(request, response, httpMsgContext)) {
		
			case LOGIN_SUCCESS:
				return SUCCESS;
				
			case LOGIN_FAILURE:
				
				// End request processing and don't try to process the handler
				//
				// Note: Most JASPIC implementations don't distinguish between return codes and only check if return is SUCCESS or not
				// Note: In the case of this SAM, login is called following a request#authenticate only, so in that case a non-SUCCESS
				//       return only means not to process the handler.
				return SEND_FAILURE; 
				
			case NO_LOGIN:
				// Do nothing (officially we need to execute the unauthenticated user protocol here, but just doing nothing
				// typically works as well, additionally for JBoss this is even better as it remembers the unauthenticated
				// user :|)
				break;
		}

		// No login request and no protected resource. Just continue.
		return SUCCESS;
	}
	
	private LoginResult isLoginRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) {
		Delegators delegators = tryGetDelegators();
		
		// This SAM is supposed to work following a call to HttpServletRequest#authenticate. Such call is in-context of the component executing it,
		// which *should* have the correct CDI contexts active to obtain our CDI delegators.
		//
		// In case this SAM is triggered at the very beginning of a request (which is before even the first Servlet Filter kicks in), those CDI
		// contexts are typically not (fully) available.
		if (delegators != null) {
			
			UsernamePasswordAuthenticator usernamePasswordAuthenticator = delegators.getAuthenticator();
			UsernameOnlyAuthenticator usernameOnlyAuthenticator = delegators.getUsernameOnlyAuthenticator();
			
			Authenticator authenticator = null;
			boolean authenticated = false;
			
			AuthParameters authParameters = httpMsgContext.getAuthParameters();
			
			if (notNull(authParameters.getUsername(), authParameters.getPassword())) {
				authenticated = usernamePasswordAuthenticator.authenticate(authParameters.getUsername(), authParameters.getPassword());
				authenticator = usernamePasswordAuthenticator;
			} else if (notNull(usernameOnlyAuthenticator, authParameters.getUsername()) && authParameters.getNoPassword()) {
				authenticated = usernameOnlyAuthenticator.authenticateWithoutPassword(authParameters.getUsername());
				authenticator = usernameOnlyAuthenticator;
			} else {
				return NO_LOGIN;
			}
			
			if (authenticated) {
			    
			    httpMsgContext.registerWithContainer(authenticator.getUserName(), authenticator.getApplicationRoles());
				
				return LOGIN_SUCCESS;
			} else {
				return LOGIN_FAILURE;
			}
			
		}
		
		return NO_LOGIN;
	}
	
	private Delegators tryGetDelegators() {
		try {
			BeanManager beanManager = Beans.getBeanManager();

			return new Delegators(
				getReferenceOrNull(UsernamePasswordAuthenticator.class, beanManager),
				getReferenceOrNull(UsernameOnlyAuthenticator.class, beanManager)
			);
		} catch (Exception e) {
			return null;
		}
	}
	
	private static class Delegators {

		private final UsernamePasswordAuthenticator authenticator;
		private final UsernameOnlyAuthenticator usernameOnlyAuthenticator;

		public Delegators(UsernamePasswordAuthenticator authenticator, UsernameOnlyAuthenticator usernameOnlyAuthenticator) {
			this.authenticator = authenticator;
			this.usernameOnlyAuthenticator = usernameOnlyAuthenticator;
		}

		public UsernamePasswordAuthenticator getAuthenticator() {
			return authenticator;
		}

		public UsernameOnlyAuthenticator getUsernameOnlyAuthenticator() {
			return usernameOnlyAuthenticator;
		}
	}
	
}