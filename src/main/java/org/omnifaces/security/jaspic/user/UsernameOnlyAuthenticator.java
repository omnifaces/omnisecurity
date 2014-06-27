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
package org.omnifaces.security.jaspic.user;

/**
 * Authenticator that "authenticates" based on the username only. This is a security sensitive operation, as no further checks are demanded
 * by the API.
 * <p>
 * This type of authenticator is useful for refreshing the name and or roles of an already logged-in user or for SU logins. 
 * 
 * @author Arjan Tijms
 *
 */
public interface UsernameOnlyAuthenticator extends Authenticator {

	boolean authenticateWithoutPassword(String username);
	
}
