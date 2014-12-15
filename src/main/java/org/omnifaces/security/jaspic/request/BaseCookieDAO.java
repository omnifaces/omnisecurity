package org.omnifaces.security.jaspic.request;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.omnifaces.security.jaspic.Utils;

public class BaseCookieDAO {

	public void save(HttpServletRequest request, HttpServletResponse response, String name, String value, Integer maxAge) {
		Cookie cookie = new Cookie(name, value);
		if (maxAge != null) {
			cookie.setMaxAge(maxAge);
		}
		cookie.setHttpOnly(true);
		cookie.setPath(Utils.isEmpty(request.getContextPath())? "/" : request.getContextPath());

		response.addCookie(cookie);
	}
	
	public Cookie get(HttpServletRequest request, String name) {
		if (request.getCookies() != null) {
			for (Cookie cookie : request.getCookies()) {
				if (name.equals(cookie.getName()) && !isEmpty(cookie)) {
					return cookie;
				}
			}
		}

		return null;
	}

	public void remove(HttpServletRequest request, HttpServletResponse response, String name) {
		Cookie cookie = new Cookie(name, null);
		cookie.setMaxAge(0);
		cookie.setPath(Utils.isEmpty(request.getContextPath())? "/" : request.getContextPath());

		response.addCookie(cookie);
	}
	
	private boolean isEmpty(Cookie cookie) {
		return cookie.getValue() == null || cookie.getValue().trim().isEmpty();
	}
	
}
