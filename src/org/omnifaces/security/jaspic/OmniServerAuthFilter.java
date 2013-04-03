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

import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.jaspic.Jaspic.authenticateFromFilter;
import static org.omnifaces.security.jaspic.Jaspic.getLastStatus;
import static org.omnifaces.util.Utils.isOneOf;

import java.io.IOException;

import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.omnifaces.filter.HttpFilter;
import org.omnifaces.security.jaspic.request.HttpServletRequestDelegator;
import org.omnifaces.security.jaspic.request.RequestData;
import org.omnifaces.security.jaspic.request.RequestDataDAO;

/**
 * This filter explicitly makes a call to {@link HttpServletRequest#authenticate(HttpServletResponse)} (via a helper method so it can be
 * recognized as an explicit call) at the start of each request.
 * <p>
 * 
 * The reason for this Filter is that in here CDI, EJB, etc are available, while in a 
 * {@link ServerAuthModule#validateRequest(javax.security.auth.message.MessageInfo, javax.security.auth.Subject, javax.security.auth.Subject)} 
 * this is for most servers not the case.
 * <p>
 * Additionally, in this Filter we can wrap the request if needed. This should be possible in <code>validateHttpRequest</code> as well, but
 * in practice no known JASPIC implementation actually supports this.
 * 
 */
public class OmniServerAuthFilter extends HttpFilter {
	
	private final RequestDataDAO requestDAO = new RequestDataDAO();
	
	@Override
	public void doFilter(HttpServletRequest request, HttpServletResponse response, HttpSession session, FilterChain chain) throws ServletException, IOException {

	    // Trigger an explicit call to the SAMs, so they will execute within a context where CDI, EJB etc is available.
		authenticateFromFilter(request, response);
		
		if (isOneOf(getLastStatus(request), SUCCESS, null)) {
			
			RequestData requestData = requestDAO.get(request);
			HttpServletRequest newRequest = request;
			
			// If there was a saved request, it means the user was originally redirected from
			// a protected resource to authenticate and is not redirected back to the original resource.
			//
			// We restore the original request here by providing a wrapped request. This will ensure the
			// original request parameters (GET + POST) as well as the original cookies etc are available again.
			if (requestData != null && requestData.matchesRequest(request)) {
				newRequest = new HttpServletRequestDelegator(request, requestData);
				requestDAO.remove(request);
			}
						
			chain.doFilter(newRequest, response);
		}
	}
	
}
