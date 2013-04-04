package org.omnifaces.security.jaspic.user;

import org.brickred.socialauth.Profile;

public interface SocialAuthenticator extends Authenticator {

	boolean authenticateOrRegister(Profile externalProfile);

}
