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

import javax.security.auth.message.module.ServerAuthModule;

public class AuthStacksBuilder {
	
	Map<String, List<Module>> stacks = new HashMap<>();
	
	public StackBuilder stack() {
		return new StackBuilder();
	}
	
	public Map<String, List<Module>> build() {
		return stacks;
	}
		
	public class StackBuilder {
	
		String name;
		List<Module> modules = new ArrayList<>();
		
		public StackBuilder name(String name) {
			this.name = name;
			return this;
		}
		
		public ModuleBuilder module() {
			return new ModuleBuilder();
		}
		
		public AuthStacksBuilder add() {
			stacks.put(name, modules);
			return AuthStacksBuilder.this;
		}
		
		public class ModuleBuilder {
			
			private Module module = new Module();
			
			public ModuleBuilder serverAuthModule(ServerAuthModule serverAuthModule) {
				module.setServerAuthModule(serverAuthModule);
				return this;
			}
			
			public ModuleBuilder controlFlag(ControlFlag controlFlag) {
				module.setControlFlag(controlFlag);
				return this;
			}
			
			public StackBuilder add() {
				modules.add(module);
				return StackBuilder.this;
			}
		}
	}

}
