package org.omnifaces.security.socialauth;

import static org.omnifaces.security.cdi.Beans.getReferenceOrNull;

import java.util.Properties;

import javax.servlet.http.HttpSession;

import org.brickred.socialauth.SocialAuthConfig;
import org.brickred.socialauth.SocialAuthManager;
import org.omnifaces.security.jaspic.user.SocialAuthPropertiesProvider;
import org.omnifaces.security.socialauth.providers.StatelessTwitterImpl;

public final class SocialAuthManagerFactory {
	
	private static final String SOCIAL_AUTH_MANAGER_SESSION = "socialAuthManager";

	public static SocialAuthManager getSocialAuthManagerFromSession(HttpSession session) {
		SocialAuthManager socialAuthManager = (SocialAuthManager) session.getAttribute(SOCIAL_AUTH_MANAGER_SESSION);
		
		if (socialAuthManager == null) {
			socialAuthManager = getSocialAuthManager();
			session.setAttribute(SOCIAL_AUTH_MANAGER_SESSION, socialAuthManager);
		}
		
		return socialAuthManager;
	}
	
	public static SocialAuthManager getSocialAuthManager() {
		try {
			SocialAuthConfig config = new SocialAuthConfig();
			
			SocialAuthPropertiesProvider propertiesProvider = getReferenceOrNull(SocialAuthPropertiesProvider.class);
			
			String twitterStatelessName = "twitter-stateless"; 
			if (propertiesProvider != null) {
				Properties properties = propertiesProvider.getProperties();
				if (properties.containsKey("twitter-stateless.name")) {
					twitterStatelessName = properties.getProperty("twitter-stateless.name");
				}
			}
			
			config.addProvider(twitterStatelessName, StatelessTwitterImpl.class);
			
			if (propertiesProvider != null) {
				config.load(propertiesProvider.getProperties());
			}
			else {
				config.load();
			}

			SocialAuthManager socialAuthManager = new SocialAuthManager();
			socialAuthManager.setSocialAuthConfig(config);
			
			return socialAuthManager;
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}
	
	public static boolean isSocialAuthManagerPresent(HttpSession session) {
		return session.getAttribute(SOCIAL_AUTH_MANAGER_SESSION) != null;
	}
	
}
