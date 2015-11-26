package org.omnifaces.security.jaspic.request;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RememberMeSettingCookieDAO extends BaseCookieDAO {

	private static final String COOKIE_NAME = "omnisecurity_remember_me";

	public void save(HttpServletRequest request, HttpServletResponse response, boolean value) {
		save(request, response, COOKIE_NAME, "" + value, null);
	}

	public Cookie get(HttpServletRequest request) {
		return get(request, COOKIE_NAME);
	}

	public void remove(HttpServletRequest request, HttpServletResponse response) {
		remove(request, response, COOKIE_NAME);
	}
}
