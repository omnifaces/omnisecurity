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

import static java.lang.Integer.parseInt;
import static java.util.Collections.enumeration;
import static java.util.Locale.US;
import static java.util.TimeZone.getTimeZone;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.omnifaces.security.jaspic.Utils;

/**
 * This class wraps a given HttpServletRequest instance and delegates "most" methods that request
 * "base data" to an also given RequestData instance.
 * 
 * @author Arjan Tijms
 *
 */
public class HttpServletRequestDelegator extends HttpServletRequestWrapper {
	
	private static final TimeZone GMT = getTimeZone("GMT");
	private static final String[] datePatterns = {
		"EE, dd MMM yyyy HH:mm:ss zz",
		"EEEE, dd-MMM-yy HH:mm:ss zz",
		"EE MMM  d HH:mm:ss yyyy"
	};
	
	private final RequestData requestData;
	private List<DateFormat> dateFormats;
	
	public HttpServletRequestDelegator(HttpServletRequest request, RequestData requestData) {
		super(request);
		this.requestData = requestData;
		
	}

	@Override
	public Cookie[] getCookies() {
		return requestData.getCookies();
	}
	
	
	// ### Headers
	
	@Override
	public Enumeration<String> getHeaderNames() {
		return enumeration(requestData.getHeaders().keySet());
	}
	
	@Override
	public String getHeader(String name) {
		
		// Return the first matching header that has the same (case insensitive) name
		for (Map.Entry<String, List<String>> header : requestData.getHeaders().entrySet()) {
			if (header.getKey().equalsIgnoreCase(name) && !header.getValue().isEmpty()) {
				return header.getValue().get(0);
			}
		}
		
		return null;
	}
	
	@Override
	public Enumeration<String> getHeaders(String name) {
		
		// Collect headers irrespective of the case that was used for the actual header
		// when submitted and the case of the name asked here.
		List<String> headers = new ArrayList<>();
		for (Map.Entry<String, List<String>> header : requestData.getHeaders().entrySet()) {
			if (header.getKey().equalsIgnoreCase(name)) {
				headers.addAll(header.getValue());
			}
		}
		
		return enumeration(headers);
	}
	
	@Override
	public int getIntHeader(String name) {
		String header = getHeader(name);
		
		if (header == null) {
			// Spec defines we should return -1 is header doesn't exist
			return -1;
		}
		
		// If header ain't an integer, spec says a NumberFormatException should be thrown,
		// which is what Integer.parseInt will do.
		return parseInt(header);
	}
	
	@Override
	public long getDateHeader(String name) {
		String header = getHeader(name);
		
		if (header == null) {
			// Spec defines we should return -1 if header doesn't exist
			return -1;
		}
		
		if (dateFormats == null) {
			dateFormats = new ArrayList<>(datePatterns.length);
			for (String datePattern : datePatterns) {
				dateFormats.add(createDateFormat(datePattern));
			}
		}
		
		for (DateFormat dateFormat : dateFormats) {
			try {
				return dateFormat.parse(header).getTime();
			} catch (ParseException e) {
				// noop
			}
		}
		
		// If no conversion is possible, spec says an IllegalArgumentException should be thrown
		throw new IllegalArgumentException("Can't convert " + header + " to a date");
	}
	
	
	
	// ### Parameters
	
	@Override
	public Map<String, String[]> getParameterMap() {
		return requestData.getParameters();
	}
	
	@Override
	public String getParameter(String name) {
		
		String[] values = requestData.getParameters().get(name);
		if (Utils.isEmpty(values)) {
			return null;
		}
		
		return values[0];
	}
	
	@Override
	public Enumeration<String> getParameterNames() {
		return enumeration(getParameterMap().keySet());
	}
	
	@Override
	public String[] getParameterValues(String name) {
		return getParameterMap().get(name);
	}
	
	
	// ### Locales
	
	@Override
	public Enumeration<Locale> getLocales() {
		return enumeration(requestData.getLocales());
	}
	
	@Override
	public Locale getLocale() {
		
		if (requestData.getLocales().isEmpty()) {
			// Is this possible? Doesn't the original HttpServletRequest#getLocales
			// already returns the default here?
			return Locale.getDefault();
		}
		
		return requestData.getLocales().get(0);
	}
	
	@Override
	public String getMethod() {
		return requestData.getMethod();
	}
	
	
	private DateFormat createDateFormat(String pattern) {
		DateFormat dateFormat = new SimpleDateFormat(pattern, US);
		dateFormat.setTimeZone(GMT);
		return dateFormat;
	}
	

}
