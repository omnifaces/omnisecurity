package org.omnifaces.security.jaspic;

import static javax.security.auth.message.AuthStatus.SUCCESS;
import static org.omnifaces.security.jaspic.Jaspic.authenticateFromFilter;
import static org.omnifaces.security.jaspic.Jaspic.getLastStatus;
import static org.omnifaces.util.Utils.isOneOf;

import java.io.IOException;

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
 * When access to the request resource is granted, this method will be invoked after validateHttpRequest.
 * <p>
 * The reason for this extra method is that in this method CDI and EJB are available, while in validateHttpRequest this is
 * for most servers not the case.
 * <p>
 * Additionally, in this method we can wrap the request if needed. This should be possible in validateHttpRequest as well, but
 * in practice no known JASPIC implementation actually supports this.
 * 
 */
public class OmniServerAuthFilter extends HttpFilter {
	
	private final RequestDataDAO requestDAO = new RequestDataDAO();
	
	@Override
	public void doFilter(HttpServletRequest request, HttpServletResponse response, HttpSession session, FilterChain chain) throws ServletException, IOException {

		authenticateFromFilter(request, response);
		
		if (isOneOf(getLastStatus(request), SUCCESS, null)) {
			
			RequestData requestData = requestDAO.get(request);
			HttpServletRequest newRequest = request;
			
			if (requestData != null && requestData.matchesRequest(request)) {
				newRequest = new HttpServletRequestDelegator(request, requestData);
				requestDAO.remove(request);
			}
						
			chain.doFilter(newRequest, response);
		}
	}
	
}
