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

import static org.omnifaces.security.jaspic.HttpServerAuthModule.IS_AUTHENTICATION_KEY;
import static org.omnifaces.security.jaspic.HttpServerAuthModule.IS_LOGOUT_KEY;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.omnifaces.util.Faces;

/**
 * A set of utility methods for using the JASPIC API, specially in combination with
 * the OmniServerAuthModule.
 * <p>
 * Note that this contains various methods that assume being called from a JSF context.
 * 
 * @author Arjan Tijms
 *
 */
public final class Jaspic {

	private Jaspic() {}
		
	public static boolean authenticate() {
		return authenticate(Faces.getRequest(), Faces.getResponse());
	}
	
	public static boolean authenticate(String username, String password, boolean rememberMe) {
		
		HttpServletRequest request = Faces.getRequest();
		
		try {
			request.setAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.USERNAME_KEY , username);
			request.setAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.PASSWORD_KEY , password);
			request.setAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.REMEMBERME_KEY , rememberMe);
		return authenticate(request, Faces.getResponse());
		} finally {
			request.removeAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.USERNAME_KEY);
			request.removeAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.PASSWORD_KEY);
			request.removeAttribute(org.omnifaces.security.jaspic.HttpServerAuthModule.REMEMBERME_KEY);
		}
	}
	
	public static boolean authenticate(HttpServletRequest request, HttpServletResponse response) {
		try {
			request.setAttribute(IS_AUTHENTICATION_KEY, true);
			return request.authenticate(response);
		} catch (ServletException | IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			request.removeAttribute(IS_AUTHENTICATION_KEY);
		}
	}
	
	public static void logout() {
		logout(Faces.getRequest(), Faces.getResponse());
	}
	
	public static void logout(HttpServletRequest request, HttpServletResponse response) {
		try {
			request.getSession().invalidate();
			request.logout();
			
			// Hack to signal to the SAM that we are logging out. Only works this way
			// for the OmniServerAuthModule.
			request.setAttribute(IS_LOGOUT_KEY, true);
			request.authenticate(response);
		} catch (ServletException | IOException e) {
			throw new IllegalArgumentException(e);
		} finally {
			request.removeAttribute(IS_LOGOUT_KEY);
		}
	}
	
	
}
