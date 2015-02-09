/*
 * Copyright 2015 OmniFaces.
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
import static org.omnifaces.security.jaspic.Utils.getSingleParameterFromState;
import static org.omnifaces.security.jaspic.Utils.isEmpty;
import static org.omnifaces.security.jaspic.Utils.serializeURLSafe;
import static org.omnifaces.security.jaspic.Utils.toQueryString;
import static org.omnifaces.security.jaspic.core.Jaspic.isAuthenticationRequest;
import static org.omnifaces.security.jaspic.core.ServiceType.AUTO_REGISTER_SESSION;
import static org.omnifaces.security.jaspic.core.ServiceType.REMEMBER_ME;
import static org.omnifaces.security.jaspic.core.ServiceType.SAVE_AND_REDIRECT;
import static org.omnifaces.security.jaspic.factory.OmniServerAuthContext.REMEMBER_ME_SESSION_NAME;
import static org.omnifaces.security.socialauth.SocialAuthManagerFactory.isSocialAuthManagerPresent;

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

@SamServices({AUTO_REGISTER_SESSION, SAVE_AND_REDIRECT, REMEMBER_ME})
public class SocialServerAuthModule extends HttpServerAuthModule {

	public static final Logger logger = Logger.getLogger(SocialServerAuthModule.class.getName());
	
	public static final String SOCIAL_PROFILE 		  = "omnisecurity.socialProfile";
	
	public static final String USE_SESSIONS 		  = "useSessions";
	public static final String CALLBACK_URL 		  = "callbackUrl";
	public static final String PROFILE_INCOMPLETE_URL = "profileIncompleteUrl";
	public static final String REGISTRATION_ERROR_URL =	"registrationErrorUrl";
	
	public boolean useSessions;
	public String callbackURL;
	public String profileIncompleteUrl;
	public String registrationErrorUrl;
	
	private StateCookieDAO stateCookieDAO = new StateCookieDAO();
	private final RequestDataDAO requestDAO = new RequestDataDAO();

	private String providerId;

	public SocialServerAuthModule(String providerId) {
		this.providerId = providerId;
	}
	
	@Override
	public void initializeModule(HttpMsgContext httpMsgContext) {
		useSessions = Boolean.valueOf(httpMsgContext.getModuleOption(USE_SESSIONS));
		callbackURL = httpMsgContext.getModuleOption(CALLBACK_URL);
		profileIncompleteUrl = httpMsgContext.getModuleOption(PROFILE_INCOMPLETE_URL);
		registrationErrorUrl = httpMsgContext.getModuleOption(REGISTRATION_ERROR_URL);
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
				
				ExtraParameters extraParameters = new ExtraParameters();
				
				if (!useSessions) {
					
					// Not using sessions for authentication
					
					// See if we can invalidate the session so we're sure to start with a clean slate for this new login
					if (checkSessionInvalidate(request)) {
					
						// Save the auth method that we used (e.g. "facebook") together with a time stamp. The time stamp
						// will be compared when the callback happens to make sure the request and callback match
						String state = generateAuthMethodState(httpMsgContext);
						stateCookieDAO.save(request, response, state);
						
						extraParameters.initParams(providerId, callbackURL, state);
					}
				} else {
					generateSessionState(httpMsgContext);
				}
				
				response.sendRedirect(
					getSocialAuthManager(httpMsgContext).getAuthenticationUrl(providerId, getBaseURL(request) + callbackURL + extraParameters.getCallbackParam()) +
					extraParameters.getProviderParam()
				);

				return true;

			}
			catch (Exception e) {
				throw (AuthException) new AuthException().initCause(e);
			}
		}
		
		return false;
	}
	
	private boolean checkSessionInvalidate(HttpServletRequest request) {
		
		RequestData requestData = requestDAO.get(request);
		if (requestData != null && requestData.isRestoreRequest()) {
			// Like the FORM authentication mechanism in Servlet, restoring a request requires the session, since
			// it stores all request data, like POST data, headers, etc.
			return false;
		}
		
		// Temporarily disable. Consider later.
		
//		HttpSession session = request.getSession(false);
//		if (session != null) {
//			// Invalidate the session so we're sure to start with a clean slate for this new login
//			session.invalidate();
//		}
		
		return true;
	}

	private boolean isCallbackRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws Exception {
		if (request.getRequestURI().equals(callbackURL)) {
			
			if (useSessions) {
				return isSocialAuthManagerPresent(request.getSession());
			} 
				
			if (!isEmpty(request.getParameter("state"))) {
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
		}
		
		return false;
	}
	
	
	private void getUserProfileFromSocialProvider(HttpServletRequest request, HttpMsgContext httpMsgContext) throws Exception {
		SocialAuthManager socialAuthManager = getSocialAuthManager(httpMsgContext);

		if (!useSessions) {
			// For some reason this doubles as a kind of init for the SocialAuthManager instance. If we got
			// a new inst
			socialAuthManager.getAuthenticationUrl(providerId, getBaseURL(request) + callbackURL);
		}
	
		AuthProvider authProvider = socialAuthManager.connect(getRequestParametersMap(request));

		Profile profile = authProvider.getUserProfile();
		request.getSession().setAttribute(SOCIAL_PROFILE, profile);
		
		if (!useSessions) {
			String redirectURL = getSingleParameterFromState(request.getParameter("state"), "redirectUrl");
			if (redirectURL != null) {
				requestDAO.saveUrlOnly(request, redirectURL);
			}
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
				
				if (!useSessions) {
					request.getSession().removeAttribute(SOCIAL_PROFILE);
				}

				return SUCCESS;
			}
		}
		catch (ProfileIncompleteException e) {
			if (e.getReason() != null && !request.getServletPath().startsWith(profileIncompleteUrl)) {
				response.sendRedirect(profileIncompleteUrl);
				
				return SEND_CONTINUE;
			}
			
			return SUCCESS; // DO NOTHING, slightly different from SUCCESS	
		}
		catch (RegistrationException e) {
			if (e.getReason() != null) {
				request.getSession().setAttribute(SOCIAL_PROFILE, null);
				response.sendRedirect(registrationErrorUrl + "?failure-reason=" + encodeURL(e.getReason()));
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
    	
    	Boolean rememberMe = httpMsgContext.getAuthParameters().getRememberMe();
    	if (rememberMe != null) {
    		parametersMap.put("rememberMe", asList(rememberMe.toString()));
    	}
		
		return serializeURLSafe(toQueryString(parametersMap));
	}
	
	private void generateSessionState(HttpMsgContext httpMsgContext) {
		Boolean rememberMe = httpMsgContext.getAuthParameters().getRememberMe();
		if (rememberMe != null) {
			httpMsgContext.getRequest().getSession().setAttribute(REMEMBER_ME_SESSION_NAME, rememberMe);
		}
	}
	
	private SocialAuthManager getSocialAuthManager(HttpMsgContext httpMsgContext) {
		if (useSessions) {
			return SocialAuthManagerFactory.getSocialAuthManagerFromSession(httpMsgContext.getRequest().getSession());
		} else {
			return SocialAuthManagerFactory.getSocialAuthManager();
		}
	}
	
	public static class ExtraParameters {
		
		private String callbackParam = "";
		private String providerParam = "";
		
		public void initParams(String providerId, String callbackURL, String state) {
			// Determine the extra parameters to send along to the provider. The provider will send these back to us.
			if (providerId.equals("twitter")) {
				// For OAuth1 providers like twitter, extra parameters are specified in the callback URL
				if (callbackURL.contains("?")) {
					callbackParam = "&state=" + state;
				} else {
					callbackParam = "?state=" + state;
				}
			} else {
				// For OAuth2 providers like facebook and google all extra parameters are in a single parameter called state, separate from the callback URL
				providerParam = "&state=" + state;
			}
		}
		
		public String getCallbackParam() {
			return callbackParam;
		}
		
		public String getProviderParam() {
			return providerParam;
		}
		
	}

}