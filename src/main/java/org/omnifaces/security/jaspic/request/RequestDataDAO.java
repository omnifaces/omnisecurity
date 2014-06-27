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

import static org.omnifaces.security.jaspic.request.RequestCopier.copy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * This class saves the data of a HttpServletRequest into the session as a RequestData instance, and has
 * methods to retrieve and remove this data again.
 *
 * @author Arjan Tijms
 *
 */
public class RequestDataDAO {

	private static final String ORIGINAL_REQUEST_DATA_SESSION_NAME = "org.omnifaces.security.jaspic.original.request";

	public void save(HttpServletRequest request) {
		request.getSession().setAttribute(ORIGINAL_REQUEST_DATA_SESSION_NAME, copy(request));
	}

	public void saveUrlOnly(HttpServletRequest request, String url) {
		RequestData requestData = new RequestData();

		requestData.setRequestURL(url);
		requestData.setRestoreRequest(false);

		request.getSession().setAttribute(ORIGINAL_REQUEST_DATA_SESSION_NAME, requestData);
	}

	public RequestData get(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return null;
		}

		return (RequestData) session.getAttribute(ORIGINAL_REQUEST_DATA_SESSION_NAME);
	}

	public void remove(HttpServletRequest request) {
		request.getSession().removeAttribute(ORIGINAL_REQUEST_DATA_SESSION_NAME);
	}

}
