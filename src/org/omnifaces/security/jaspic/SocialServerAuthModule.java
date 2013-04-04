package org.omnifaces.security.jaspic;

import java.util.Map;

import javax.security.auth.message.AuthStatus;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.brickred.socialauth.AuthProvider;
import org.brickred.socialauth.Profile;
import org.brickred.socialauth.SocialAuthConfig;
import org.brickred.socialauth.SocialAuthManager;
import org.brickred.socialauth.util.SocialAuthUtil;
import org.omnifaces.security.cdi.Beans;
import org.omnifaces.security.jaspic.user.SocialAuthenticator;

public class SocialServerAuthModule extends HttpServerAuthModule {

	private static final String SOCIAL_AUTH_MANAGER = "socialAuthManager";

	@Override
	public AuthStatus validateHttpRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) {

		if (isLoginRequest(request, response)) {
			return AuthStatus.SEND_CONTINUE;
		}

		try {
			if (isCallbackRequest(request, response, httpMsgContext)) {
				return AuthStatus.SUCCESS;
			}
		}
		catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return AuthStatus.FAILURE;
		}

		return AuthStatus.SUCCESS;
	}

	private boolean isCallbackRequest(HttpServletRequest request, HttpServletResponse response, HttpMsgContext httpMsgContext) throws Exception {
		SocialAuthManager manager = (SocialAuthManager) request.getSession().getAttribute(SOCIAL_AUTH_MANAGER);

		if (manager != null && request.getRequestURI().endsWith("/login")) {
			Map<String, String> requestParametersMap = SocialAuthUtil.getRequestParametersMap(request);
			AuthProvider authProvider = manager.connect(requestParametersMap);


			SocialAuthenticator authenticator = Beans.getReference(SocialAuthenticator.class);
			Profile profile = authProvider.getUserProfile();

			authenticator.authenticateOrRegister(profile); // TODO do something with return type

			request.getSession().setAttribute(SOCIAL_AUTH_MANAGER, null);

			httpMsgContext.registerWithContainer(authenticator.getUserName(), authenticator.getApplicationRoles());

			return true;
		}

		return false;
	}

	private boolean isLoginRequest(HttpServletRequest request, HttpServletResponse response) {

		SocialAuthManager manager = (SocialAuthManager) request.getSession().getAttribute(SOCIAL_AUTH_MANAGER);
		if(manager == null && request.getRequestURI().endsWith("/facebook")) {
			SocialAuthConfig config = new SocialAuthConfig();

			try {
				config.load();

				manager = new SocialAuthManager();
				manager.setSocialAuthConfig(config);

				request.getSession().setAttribute(SOCIAL_AUTH_MANAGER, manager);

				response.sendRedirect(manager.getAuthenticationUrl("facebook", "http://localhost:8080/login"));

				return true;

			}
			catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		return false;
	}

}
