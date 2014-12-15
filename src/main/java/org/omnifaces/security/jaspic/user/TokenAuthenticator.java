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
 * An authenticator that can do authentication based on a token it previously generated
 * for an already authenticated user.
 * <p>
 * The intend for this authenticator is to generate a (temporary) token that's associated
 * with a user for the purpose of a "remember me" facility.
 * 
 * @author Arjan Tijms
 *
 */
public interface TokenAuthenticator extends Authenticator {
	
	boolean authenticate(String token);
	String generateLoginToken();
	void removeLoginToken(String token);

}
