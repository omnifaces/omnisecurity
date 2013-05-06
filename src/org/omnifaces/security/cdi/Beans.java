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
package org.omnifaces.security.cdi;

import java.lang.annotation.Annotation;

import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.naming.InitialContext;
import javax.naming.NamingException;

/**
 * The obligatory CDI utility class to obtain a reference to CDI's BeanManager.
 * 
 * @author Arjan Tijms
 *
 */
public class Beans {
	
	public static <T> T getReference(Class<T> beanClass) {
		return getReference(beanClass, getBeanManager());
	}

	@SuppressWarnings("unchecked")
	public static <T> T getReference(Class<T> beanClass, BeanManager beanManager) {

		Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(beanClass));

		return (T) beanManager.getReference(bean, beanClass, beanManager.createCreationalContext(bean));
	}
	
	@SuppressWarnings("unchecked")
	public static <T> T getReferenceOrNull(Class<T> beanClass, BeanManager beanManager) {
		try {
			Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(beanClass));

			return (T) beanManager.getReference(bean, beanClass, beanManager.createCreationalContext(bean));
		} catch (Exception e) {
			return null;
		}
	}

	public static <T> T getInstance(final Class<T> type, final Class<? extends Annotation> scope) {
		return getInstance(type, scope, getBeanManager());
	}

	public static <T> T getInstance(final Class<T> type, final Class<? extends Annotation> scope, final BeanManager beanManager) {
		
		@SuppressWarnings("unchecked")
		Bean<T> bean = (Bean<T>) beanManager.resolve(beanManager.getBeans(type));

		return beanManager.getContext(scope).get(bean, beanManager.createCreationalContext(bean));
	}
	
	public static BeanManager tryGetBeanManager() {
		try {
			return getBeanManager();
		} catch (IllegalStateException e) {
			return null;
		}
	}
	
	public static BeanManager getBeanManager() {
		InitialContext context = null;
		try {
			context = new InitialContext();
			return (BeanManager) context.lookup("java:comp/BeanManager");
		} catch (NamingException e) {
			throw new IllegalStateException(e);
		} finally {
			closeContext(context);
		}
	}
	
	private static void closeContext(InitialContext context) {
		try {
			if (context != null) {
				context.close();
			}
		} catch (NamingException e) {
			throw new RuntimeException(e);
		}
	}

}
