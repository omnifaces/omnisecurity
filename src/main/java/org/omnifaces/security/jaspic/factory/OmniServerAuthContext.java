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
package org.omnifaces.security.jaspic.factory;

import static java.util.logging.Level.FINE;
import static javax.security.auth.message.AuthStatus.FAILURE;
import static org.omnifaces.security.jaspic.Utils.getSingleParameterFromQueryString;
import static org.omnifaces.security.jaspic.Utils.isEmpty;
import static org.omnifaces.security.jaspic.Utils.toParameterMap;
import static org.omnifaces.security.jaspic.Utils.unserializeURLSafe;

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthContext;
import javax.servlet.http.HttpServletRequest;

import org.omnifaces.security.jaspic.config.AuthStacks;
import org.omnifaces.security.jaspic.config.Module;
import org.omnifaces.security.jaspic.core.AuthResult;
import org.omnifaces.security.jaspic.core.Jaspic;

/**
 * The Server Authentication Context is an extra (required) indirection between the Application Server and the actual Server Authentication Module
 * (SAM). This can be used to encapsulate any number of SAMs and either select one at run-time, invoke them all in order, etc.
 * <p>
 * This auth context implements the algorithm for a JAAS/PAM like stacking of auth modules and simulates some JASPIC MR2 (Java EE 7)
 * features for use in a JASPIC MR1 (Java EE 6) environment such as delivering a logout call to the auth modules and automatically
 * creating an authentication session.
 * <p>
 * This auth context is also instrumental on working around the CDI limitation of JASPIC; a protected request is always redirected
 * to a public resource, where a Filter does an explicit call for authentication. Container calls are not delegated to the SAMs, only
 * explicit calls are. This ensures at the cost of an extra redirect that SAMs always execute within a context where CDI, EJB etc is available
 * and where forwards on the passed-in request instance work.
 * <p>
 * Note: As explained above, parts of this implementation are redundant with JASPIC 1.0 MR2. Hopefully the Filter workaround will
 * be redundant too with some future version of JASPIC.
 *
 * @author Arjan Tijms
 *
 */
public class OmniServerAuthContext implements ServerAuthContext {

	// TODO: Session state needs to be handled much better. This is one of the things that has to be fixed
	// before a 1.0 release. The below names are temporary while OmniSecurity 0.x is in alpha.
	public static final String AUTH_METHOD_SESSION_NAME = "org.omnifaces.security.jaspic.AuthMethod";
	public static final String REMEMBER_ME_SESSION_NAME = "org.omnifaces.security.jaspic.RememberMe";

	private static final Logger logger = Logger.getLogger(OmniServerAuthContext.class.getName());

	private AuthStacks stacks;
	private boolean onlyOneModule;

	public OmniServerAuthContext(CallbackHandler handler, AuthStacks stacks) throws AuthException {

		this.stacks = stacks;

		if (stacks.getModuleStacks().size() == 1) {
			onlyOneModule = true;
		}

		for (List<Module> modules : stacks.getModuleStacks().values()) {
			for (Module module : modules) {
				module.getServerAuthModule().initialize(null, null, handler, module.getOptions());
			}
		}
	}

	@Override
	public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {

		AuthStatus status = doValidateRequest(messageInfo, clientSubject, serviceSubject);
		Jaspic.setLastStatus((HttpServletRequest) messageInfo.getRequestMessage(), status);

		return status;
	}

	public AuthStatus doValidateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException {

		HttpServletRequest request = (HttpServletRequest) messageInfo.getRequestMessage();

		boolean requiredFailed = false;
		AuthResult finalAuthResult = new AuthResult();

		for (Module module : getModuleStack(request)) {

			AuthResult authResult = Jaspic.validateRequest(module.getServerAuthModule(), messageInfo, clientSubject, serviceSubject);

			if (authResult.getAuthStatus() == FAILURE) {
	            throw new IllegalStateException("Servlet Container Profile SAM should not return status FAILURE. This is for CLIENT SAMs only");
	        }

			finalAuthResult.add(authResult);

			switch (module.getControlFlag()) {

				case REQUIRED:
					if (authResult.isFailed()) {
						requiredFailed = true;
					}
					break;

				case REQUISITE:
					if (authResult.isFailed()) {
						return finalAuthResult.throwOrFail();
					}
					break;

				case SUFFICIENT:
					if (!authResult.isFailed() && !requiredFailed) {
						return authResult.getAuthStatus();
					}
					break;

				case OPTIONAL:
					// Do nothing
					break;
			}
		}

		return finalAuthResult.throwOrReturnStatus();
	}

	@Override
	public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {

		AuthStatus authStatus = null;
		for (Module module : getModuleStack((HttpServletRequest) messageInfo.getRequestMessage())) {
			authStatus = module.getServerAuthModule().secureResponse(messageInfo, serviceSubject);
		}

		return authStatus;
	}

	@Override
	public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
		for (Module module : getModuleStack((HttpServletRequest) messageInfo.getRequestMessage())) { // tmp
			module.getServerAuthModule().cleanSubject(messageInfo, subject);
		}
	}

	private List<Module> getModuleStack(HttpServletRequest request) {

		String authMethod = Jaspic.getAuthParameters(request).getAuthMethod();

		if (authMethod == null) {

			// Currently depends on the auth module to set this in a callback URL.
			// TODO: this needs much better handling
			String state = getSingleParameterFromQueryString(request.getQueryString(), "state");

			if (!isEmpty(state)) {
				try {
					Map<String, List<String>> requestStateParameters = toParameterMap(unserializeURLSafe(state));
					if (!isEmpty(requestStateParameters.get("authMethod"))) {
						authMethod = requestStateParameters.get("authMethod")
						                                   .get(0);
					}
				}
				catch (IllegalArgumentException e) {
					logger.log(FINE, "Unable to decode state parameter:", e);
				}
			}

			if (authMethod == null && !onlyOneModule) {
				try {
					authMethod = (String) request.getSession().getAttribute(AUTH_METHOD_SESSION_NAME);
				} catch (IllegalStateException e) {
					// Ignore
				}
			}

			if (authMethod == null) {
				authMethod = stacks.getDefaultStackName();
			}
		}

		if (!onlyOneModule) {
			// If there's more than one module, remember the auth method in the session.
			// This is needed so that after repeated interactions with the user we keep
			// using the same auth method.
			// TODO: Have several options here:
			// * Don't save auth method (assumes no module goes into a dialog with the user)
			// * Save auth method in session
			// * Save auth method in cookie
			// * Save auth method custom (use plug-in)
			try {
				request.getSession().setAttribute(AUTH_METHOD_SESSION_NAME, authMethod);
			} catch (IllegalStateException e) {
				// Ignore
			}
		}

		return stacks.getModuleStacks().get(authMethod);
	}

}