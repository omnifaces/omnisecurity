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
package org.omnifaces.security.jaspic.request;

import static java.util.concurrent.TimeUnit.DAYS;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class takes care of saving the login token cookie to the response, retrieving it from
 * a request or removing it.
 * 
 * @author Arjan Tijms
 *
 */
public class LoginTokenCookieDAO extends BaseCookieDAO {
	
	private static final String COOKIE_NAME = "omnisecurity_login_token";
	private static final int MAX_AGE = (int) DAYS.toSeconds(14);

	public void save(HttpServletRequest request, HttpServletResponse response, String value) {
		save(request, response, COOKIE_NAME, value, MAX_AGE);
	}
	
	public Cookie get(HttpServletRequest request) {
		return get(request, COOKIE_NAME);
	}

	public void remove(HttpServletRequest request, HttpServletResponse response) {
		remove(request, response, COOKIE_NAME);
	}
	
}
