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
package org.omnifaces.security.jaspic.config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.security.auth.message.module.ServerAuthModule;

public class AuthStacksBuilder {
	
	AuthStacks authStacks = new AuthStacks();
	
	public StackBuilder stack() {
		return new StackBuilder();
	}
	
	public AuthStacks build() {
		// If there's no default, take first.
		if (authStacks.getDefaultStackName() == null && authStacks.getModuleStacks().size() > 0) {
			authStacks.setDefaultStackName(authStacks.getModuleStacks().keySet().iterator().next());
		}
		
		return authStacks;
	}
		
	public class StackBuilder {
	
		String name;
		boolean isDefault;
		List<Module> modules = new ArrayList<>();
		
		public StackBuilder name(String name) {
			this.name = name;
			return this;
		}
		
		public StackBuilder setDefault() {
			isDefault = true;
			return this;
		}
		
		public ModuleBuilder module() {
			return new ModuleBuilder();
		}
		
		public AuthStacksBuilder add() {
			if (name == null) {
				name = UUID.randomUUID().toString();
			}
			if (isDefault) {
				authStacks.setDefaultStackName(name);
			}
			authStacks.getModuleStacks().put(name, modules);
			return AuthStacksBuilder.this;
		}
		
		public class ModuleBuilder {
			
			private Module module = new Module();
			private Map<String, String> options = new HashMap<String, String>();
			
			public ModuleBuilder serverAuthModule(ServerAuthModule serverAuthModule) {
				module.setServerAuthModule(serverAuthModule);
				return this;
			}
			
			public ModuleBuilder controlFlag(ControlFlag controlFlag) {
				module.setControlFlag(controlFlag);
				return this;
			}
			
			public ModuleBuilder options(Map<String, String> options) {
				options.putAll(options);
				return this;
			}
			
			public ModuleBuilder option(String key, String value) {
				options.put(key, value);
				return this;
			}
			
			public StackBuilder add() {
				module.setOptions(options);
				modules.add(module);
				return StackBuilder.this;
			}
		}
	}
}