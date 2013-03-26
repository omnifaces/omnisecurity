package org.omnifaces.security.jaspic.config;

import javax.security.auth.message.module.ServerAuthModule;

public class Module {

	private ServerAuthModule serverAuthModule;
	private ControlFlag controlFlag;

	public ServerAuthModule getServerAuthModule() {
		return serverAuthModule;
	}

	public void setServerAuthModule(ServerAuthModule serverAuthModule) {
		this.serverAuthModule = serverAuthModule;
	}

	public ControlFlag getControlFlag() {
		return controlFlag;
	}

	public void setControlFlag(ControlFlag controlFlag) {
		this.controlFlag = controlFlag;
	}

}
