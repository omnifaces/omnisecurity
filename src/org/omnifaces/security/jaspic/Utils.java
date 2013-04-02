package org.omnifaces.security.jaspic;

import static org.omnifaces.util.Utils.coalesce;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Utils {
	
	public static boolean notNull(Object... objects) {
		return coalesce(objects) != null;
	}
	
	public static String getBaseURL(HttpServletRequest request) {
		String url = request.getRequestURL().toString();
		return url.substring(0, url.length() - request.getRequestURI().length()) + request.getContextPath();
	}
	
	public static void redirect(HttpServletResponse response, String location) {
		try {
			response.sendRedirect(location);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}

}
