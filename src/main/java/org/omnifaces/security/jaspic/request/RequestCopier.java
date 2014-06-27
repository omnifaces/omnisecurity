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

import static java.util.Arrays.copyOf;
import static java.util.Collections.emptyMap;
import static java.util.Collections.list;
import static org.omnifaces.util.Utils.isEmpty;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * This class copies all "base data" from a given request. The goal is that this copied data can be used
 * later to restore a request, by wrapping a new request and delegating methods that fetch data
 * from that request to the copied data.
 * 
 * @author Arjan Tijms
 *
 */
public final class RequestCopier {
	
	private RequestCopier() {}

	public static RequestData copy(HttpServletRequest request) {
		
		RequestData requestData = new RequestData();
		
		requestData.setCookies(copyCookies(request.getCookies()));
		requestData.setHeaders(copyHeaders(request));
		requestData.setParameters(copyParameters(request.getParameterMap()));
		requestData.setLocales(list(request.getLocales()));
		
		requestData.setMethod(request.getMethod());
		requestData.setRequestURL(request.getRequestURL().toString());
		requestData.setQueryString(request.getQueryString());
	
		return requestData;
	}
	
	
	private static Cookie[] copyCookies(Cookie[] cookies) {
		
		if (isEmpty(cookies)) {
			return cookies;
		}
		
		ArrayList<Cookie> copiedCookies = new ArrayList<>();
		for (Cookie cookie : cookies) {
			copiedCookies.add((Cookie)cookie.clone());
		}
		
		return copiedCookies.toArray(new Cookie[copiedCookies.size()]);
	}
	
	private static Map<String, List<String>> copyHeaders(HttpServletRequest request) {
	
		Map<String, List<String>> copiedHeaders = new HashMap<>();
		for (String headerName : list(request.getHeaderNames())) {
			copiedHeaders.put(headerName, list(request.getHeaders(headerName)));
		}
		
		return copiedHeaders;
	}
	
	private static Map<String, String[]> copyParameters(Map<String, String[]> parameters) {
		
		if (isEmptyMap(parameters)) {
			return emptyMap();
		}
		
		Map<String, String[]> copiedParameters = new HashMap<>();
		for (Map.Entry<String, String[]> parameter : parameters.entrySet()) {
			copiedParameters.put(parameter.getKey(), copyOf(parameter.getValue(), parameter.getValue().length));
		}
		
		return copiedParameters;
	}
	
	private static boolean isEmptyMap(Map<?, ?> map) {
		return map == null || map.isEmpty();
	}
	
}
