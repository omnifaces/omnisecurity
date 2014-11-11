/*
 * Copyright 2014 OmniFaces.
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
package org.omnifaces.security.constraints;

import static javax.validation.constraintvalidation.ValidationTarget.PARAMETERS;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.constraintvalidation.SupportedValidationTarget;

@SupportedValidationTarget(PARAMETERS)
public class RolesAllowedValidator implements ConstraintValidator<RolesAllowed, Object[]> {

	private String[] roles;
	
	@Inject
	private HttpServletRequest request;
	
	@EJB
	private EJBSecurityBean securityBean;

	@Override
	public void initialize(RolesAllowed constraintAnnotation) {
		roles = constraintAnnotation.value();
	}

	@Override
	public boolean isValid(final Object[] parameters, final ConstraintValidatorContext context) {
		
		for (String role : roles) {
			if (request != null) {
				if (request.isUserInRole(role)) {
					return true;
				}
			} else {
				if (securityBean.isUserInRole(role)) {
					return true;
				}
			}
		}
		
		return false;		
	}

}