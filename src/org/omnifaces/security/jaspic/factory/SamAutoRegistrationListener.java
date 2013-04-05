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

import static org.omnifaces.security.jaspic.config.ControlFlag.REQUIRED;

import javax.security.auth.message.config.AuthConfigFactory;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.omnifaces.security.jaspic.OmniServerAuthFilter;
import org.omnifaces.security.jaspic.OmniServerAuthModule;
import org.omnifaces.security.jaspic.SocialServerAuthModule;
import org.omnifaces.security.jaspic.config.AuthStacks;
import org.omnifaces.security.jaspic.config.AuthStacksBuilder;

/**
 * This listener automatically registers the SAM when the web application is starting.
 * <p>
 * NOTE: Because of an omission in the JASPIC spec there currently does not seem to be a
 * way to register the SAM just for the current web app. Registration is done for ALL
 * apps running on the server, which could be a serious problem.
 *
 * @author Arjan Tijms
 *
 */
@WebListener
public class SamAutoRegistrationListener implements ServletContextListener {

	@Override
	public void contextInitialized(ServletContextEvent sce) {

		// Example

		/*
		new AuthStacksBuilder()

			.stack()
				.name("jsf-form")
				.module()
					.serverAuthModule(new OmniServerAuthModule())
					.controlFlag(REQUIRED)
					.add()

				.module()
					.serverAuthModule(new OmniServerAuthModule())
					.controlFlag(OPTIONAL)
					.add()
				.add()

			.stack()
				.name("OpenID-Google")
				.module()
					.serverAuthModule(new OmniServerAuthModule())
					.controlFlag(REQUIRED)
					.add()
				.add()
			.build();
			*/

		 AuthStacks stacks = new AuthStacksBuilder()

		 	.stack()
		 		.name("jsf-form")
		 		.setDefault()
		 		.module()
					.serverAuthModule(new OmniServerAuthModule())
					.controlFlag(REQUIRED)
					.add()
				.add()
		 	.stack()
		 		.name("social-authentication-facebook")
		 		.module()
					.serverAuthModule(new SocialServerAuthModule("facebook"))
					.controlFlag(REQUIRED)
					.add()
				.add()
		 	.stack()
		 		.name("social-authentication-twitter")
		 		.module()
					.serverAuthModule(new SocialServerAuthModule("twitter"))
					.controlFlag(REQUIRED)
					.add()
				.add()
		 	.stack()
		 		.name("social-authentication-linkedin")
		 		.module()
					.serverAuthModule(new SocialServerAuthModule("linkedin"))
					.controlFlag(REQUIRED)
					.add()
				.add()
			.build();


		// Register the factory-factory-factory for the SAM
		AuthConfigFactory.getFactory().registerConfigProvider(
			new OmniAuthConfigProvider(stacks),
			"HttpServlet", null, "OmniSecurity authentication config provider"
		);


		// Register the SAM separately as a filter
		sce.getServletContext().addFilter(
			OmniServerAuthFilter.class.getName(),
			OmniServerAuthFilter.class
		).addMappingForUrlPatterns(null, false, "/*");
	}

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
	}
}