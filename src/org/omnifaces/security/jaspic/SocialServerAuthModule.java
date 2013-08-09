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

import static javax.security.auth.message.AuthStatus.SEND_CONTINUE;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.brickred.socialauth.util.SocialAuthUtil.getRequestParametersMap;
import static org.omnifaces.security.jaspic.Jaspic.isAuthenticationRequest;
import static org.omnifaces.security.jaspic.Utils.getBaseURL;
import static org.omnifaces.util.Utils.encodeURL;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.SocialAuthConfig;
import org.brickred.socialauth.SocialAuthManager;
import org.omnifaces.security.cdi.Beans;
import org.omnifaces.security.jaspic.user.SocialAuthPropertiesProvider;
import org.omnifaces.security.jaspic.user.SocialAuthenticator;

public class SocialServerAuthModule extends HttpServerAuthModule {

	private static final String SOCIAL_AUTH_MANAGER = "socialAuthManager";

	private String providerId;

	public SocialServerAuthModule(String providerId) {
		this.providerId = providerId;
	}

	@Override
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext)
			throws AuthException {

		// Check if user code has triggered the SAM to start the authentication process. If so the SAM will redirect the user to the social provider.
		if (isLoginRequest(request, response, httpMsgContext)) {
			return SEND_CONTINUE;
		}

		try {
			// Check if the user has arrived back from the social provider
			if (isCallbackRequest(request, response, httpMsgContext)) {

				if (doSocialLogin(request, response, httpMsgContext)) {
					return SUCCESS;
				} else {
					return SEND_FAILURE;
				}
			}
		}
		catch (Exception e) {
			throw (AuthException) new AuthException().initCause(e);
		}

		return SUCCESS;
	}

	private boolean isCallbackRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws Exception {
		if (request.getRequestURI().equals("/login") && request.getSession().getAttribute(SOCIAL_AUTH_MANAGER) != null) {
			return true;
		}

		return false;
	}

	private boolean doSocialLogin(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws Exception {
		SocialAuthManager socialAuthManager = (SocialAuthManager) request.getSession().getAttribute(SOCIAL_AUTH_MANAGER);
		request.getSession().setAttribute(SOCIAL_AUTH_MANAGER, null);
		
		AuthProvider authProvider = socialAuthManager.connect(getRequestParametersMap(request));

		SocialAuthenticator authenticator = Beans.getReference(SocialAuthenticator.class);
		Profile profile = authProvider.getUserProfile();

		try {
			if (authenticator.authenticateOrRegister(profile)) {
				httpMsgContext.registerWithContainer(authenticator.getUserName(), authenticator.getApplicationRoles());

				return true;
			}
		}
		catch (RegistrationException e) {
			if (e.getReason() != null) {
				response.sendRedirect("/login?failure-reason=" + encodeURL(e.getReason()));
			}
		}
		return false;
	}

	private boolean isLoginRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws AuthException {

		SocialAuthManager socialAuthManager = (SocialAuthManager) request.getSession().getAttribute(SOCIAL_AUTH_MANAGER);

		if (socialAuthManager == null && isAuthenticationRequest(request)) {
			SocialAuthConfig config = new SocialAuthConfig();

			try {

				SocialAuthPropertiesProvider propertiesProvider = Beans.getReferenceOrNull(SocialAuthPropertiesProvider.class);
				if (propertiesProvider != null) {
					config.load(propertiesProvider.getProperties());
				}
				else {
					config.load();
				}

				socialAuthManager = new SocialAuthManager();
				socialAuthManager.setSocialAuthConfig(config);

				request.getSession().setAttribute(SOCIAL_AUTH_MANAGER, socialAuthManager);

				response.sendRedirect(socialAuthManager.getAuthenticationUrl(providerId, getBaseURL(request) + "/login"));

				return true;

			}
			catch (Exception e) {
				AuthException authException = new AuthException();
				authException.initCause(e);

				throw authException;
			}

		}
		return false;
	}

}
