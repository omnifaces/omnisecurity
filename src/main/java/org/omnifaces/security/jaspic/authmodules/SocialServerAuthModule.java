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

import static java.lang.System.currentTimeMillis;
import static java.util.Arrays.asList;
import static java.util.logging.Level.WARNING;
import static javax.security.auth.message.AuthStatus.SEND_CONTINUE;
import static javax.security.auth.message.AuthStatus.SEND_FAILURE;
import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.brickred.socialauth.util.SocialAuthUtil.getRequestParametersMap;
import static org.omnifaces.security.jaspic.Utils.encodeURL;
import static org.omnifaces.security.jaspic.Utils.getBaseURL;
import static org.omnifaces.security.jaspic.Utils.isEmpty;
import static org.omnifaces.security.jaspic.Utils.serializeURLSafe;
import static org.omnifaces.security.jaspic.Utils.toParameterMap;
import static org.omnifaces.security.jaspic.Utils.toQueryString;
import static org.omnifaces.security.jaspic.Utils.unserializeURLSafe;
import static org.omnifaces.security.jaspic.core.Jaspic.isAuthenticationRequest;
import static org.omnifaces.security.jaspic.core.ServiceType.AUTO_REGISTER_SESSION;
import static org.omnifaces.security.jaspic.core.ServiceType.SAVE_AND_REDIRECT;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.SocialAuthManager;
import org.omnifaces.security.cdi.Beans;
import org.omnifaces.security.jaspic.core.HttpMsgContext;
import org.omnifaces.security.jaspic.core.HttpServerAuthModule;
import org.omnifaces.security.jaspic.core.SamServices;
import org.omnifaces.security.jaspic.exceptions.ProfileIncompleteException;
import org.omnifaces.security.jaspic.exceptions.RegistrationException;
import org.omnifaces.security.jaspic.request.RequestData;
import org.omnifaces.security.jaspic.request.RequestDataDAO;
import org.omnifaces.security.jaspic.request.StateCookieDAO;
import org.omnifaces.security.jaspic.user.SocialAuthenticator;
import org.omnifaces.security.socialauth.SocialAuthManagerFactory;

@SamServices({AUTO_REGISTER_SESSION, SAVE_AND_REDIRECT})
public class SocialServerAuthModule extends HttpServerAuthModule {

	public static final Logger logger = Logger.getLogger(SocialServerAuthModule.class.getName());
	
	public static final String SOCIAL_PROFILE 		= "omnisecurity.socialProfile";
	public static final String CALLBACK_URL 		  = "callbackUrl";
	public static final String PROFILE_INCOMPLETE_URL = "profileIncompleteUrl";
	public static final String REGISTRATION_ERROR_URL =	"registrationErrorUrl";
	
	public boolean useSessions;
	
	private StateCookieDAO stateCookieDAO = new StateCookieDAO();
	private final RequestDataDAO requestDAO = new RequestDataDAO();

	private String providerId;

	public SocialServerAuthModule(String providerId) {
		this.providerId = providerId;
	}
	
	@Override
	public void initializeModule(HttpMsgContext httpMsgContext) {
		useSessions = Boolean.valueOf(httpMsgContext.getModuleOption("useSessions"));
	}

	@Override
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws AuthException {

		// Check if user code has triggered the SAM to start the authentication process. If so the SAM will redirect the user to the social provider.
		if (isLoginRequest(request, response, httpMsgContext)) {
			return SEND_CONTINUE;
		}

		try {
			// Check if the user has arrived back from the social provider
			if (isCallbackRequest(request, response, httpMsgContext)) {
				// Contact the social provider directly (don't involve the user) with the tokens from the request
				// in order to get the users identity.
				getUserProfileFromSocialProvider(request, httpMsgContext);
			}
			
			// See if the social profile is available. This can be either directly after the arrival from the social provider
			// or after posting back a page where the SAM asked for more information.
			if (isProfileAvailable(request)) {
				return doSocialLogin(request, response, httpMsgContext);
				
			}
		}
		catch (Exception e) {
			throw (AuthException) new AuthException().initCause(e);
		}

		return SUCCESS;
	}
	
	private boolean isLoginRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws AuthException {

		if (isAuthenticationRequest(request)) {

			try {
				// See if we can invalidate the session so we're sure to start with a clean slate for this new login
				checkSessionInvalidate(request);
				
				// Save the auth method that we used (e.g. "facebook") together with a time stamp. The time stamp
				// will be compared when the callback happens to make sure the request and callback match
				String state = generateAuthMethodState(httpMsgContext);
				stateCookieDAO.save(request, response, state);

				response.sendRedirect(
					getSocialAuthManager(httpMsgContext).getAuthenticationUrl(providerId, getBaseURL(request) + httpMsgContext.getModuleOption(CALLBACK_URL)) +
					"&state=" + state
				);

				return true;

			}
			catch (Exception e) {
				throw (AuthException) new AuthException().initCause(e);
			}
		}
		
		return false;
	}
	
	private void checkSessionInvalidate(HttpServletRequest request) {
		
		RequestData requestData = requestDAO.get(request);
		if (requestData != null && requestData.isRestoreRequest()) {
			// Like the FORM authentication mechanism in Servlet, restoring a request requires the session, since
			// it stores all request data, like POST data, headers, etc.
			return;
		}
		
		HttpSession session = request.getSession(false);
		if (session != null) {
			// Invalidate the session so we're sure to start with a clean slate for this new login
			session.invalidate();
		}
	}

	private boolean isCallbackRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws Exception {
		if (request.getRequestURI().equals(httpMsgContext.getModuleOption(CALLBACK_URL)) && !isEmpty(request.getParameter("state"))) {
			
			try {
				String state = request.getParameter("state");
				Cookie cookie = stateCookieDAO.get(request);
				
				if (cookie != null && state.equals(cookie.getValue())) {
					return true;
				} else {
					logger.log(WARNING, 
						"State parameter provided with callback URL, but did not match cookie. " + 
						"State param value: " + state + " " +
						"Cookie value: " + (cookie == null? "<no cookie>" : cookie.getValue())
					);
				}
			} finally {
				stateCookieDAO.remove(request, response);
			}
		}

		return false;
	}
	
	private void getUserProfileFromSocialProvider(HttpServletRequest request, HttpMsgContext httpMsgContext) throws Exception {
		SocialAuthManager socialAuthManager = getSocialAuthManager(httpMsgContext);

		// For some reason this doubles as a kind of init for the SocialAuthManager instance.
		socialAuthManager.getAuthenticationUrl(providerId, getBaseURL(request) + httpMsgContext.getModuleOption(CALLBACK_URL));
	
		AuthProvider authProvider = socialAuthManager.connect(getRequestParametersMap(request));

		Profile profile = authProvider.getUserProfile();
		request.getSession().setAttribute(SOCIAL_PROFILE, profile);
		
		Map<String, List<String>> requestStateParameters = toParameterMap(unserializeURLSafe(request.getParameter("state")));
		
		List<String> redirectUrlValues = requestStateParameters.get("redirectUrl");
		if (!isEmpty(redirectUrlValues)) {
			requestDAO.saveUrlOnly(request, redirectUrlValues.get(0));
		}
	}
	
	private boolean isProfileAvailable(HttpServletRequest request) {
		return request.getSession().getAttribute(SOCIAL_PROFILE) != null;
	}

	private AuthStatus doSocialLogin(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws Exception {
		Profile profile = (Profile) request.getSession().getAttribute(SOCIAL_PROFILE);

		SocialAuthenticator authenticator = Beans.getReference(SocialAuthenticator.class);
		try {
			if (authenticator.authenticateOrRegister(profile)) {
				httpMsgContext.registerWithContainer(authenticator.getUserName(), authenticator.getApplicationRoles());

				return SUCCESS;
			}
		}
		catch (ProfileIncompleteException e) {
			if (e.getReason() != null && !request.getServletPath().startsWith(httpMsgContext.getModuleOption(PROFILE_INCOMPLETE_URL))) {
				response.sendRedirect(httpMsgContext.getModuleOption(PROFILE_INCOMPLETE_URL));
				
				return SEND_CONTINUE;
			}
			
			return SUCCESS; // DO NOTHING, slightly different from SUCCESS	
		}
		catch (RegistrationException e) {
			if (e.getReason() != null) {
				request.getSession().setAttribute(SOCIAL_PROFILE, null);
				response.sendRedirect(httpMsgContext.getModuleOption(REGISTRATION_ERROR_URL) + "?failure-reason=" + encodeURL(e.getReason()));
			}
		}
		
		return SEND_FAILURE;
	}
	
	private String generateAuthMethodState(HttpMsgContext httpMsgContext) {
		Map<String, List<String>> parametersMap = new HashMap<>();
		parametersMap.put("authMethod", asList(httpMsgContext.getAuthParameters().getAuthMethod()));
		parametersMap.put("timeStamp", asList(currentTimeMillis() + ""));
		
		String redirectUrl = httpMsgContext.getAuthParameters().getRedirectUrl();
    	if (redirectUrl != null) {
    		parametersMap.put("redirectUrl", asList(redirectUrl));
    	}
		
		return serializeURLSafe(toQueryString(parametersMap));
	}
	
	private SocialAuthManager getSocialAuthManager(HttpMsgContext httpMsgContext) {
		if (useSessions) {
			return SocialAuthManagerFactory.getSocialAuthManagerFromSession(httpMsgContext.getRequest().getSession());
		} else {
			return SocialAuthManagerFactory.getSocialAuthManager();
		}
	}

}