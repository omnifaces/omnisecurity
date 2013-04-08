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
package org.omnifaces.security.jaspic;

import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.ServerAuthContext;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A convenience context that provides access to JASPIC Servlet Profile specific types
 * and functionality.
 * 
 * @author Arjan Tijms
 *
 */
public class HttpMsgContext {

    private CallbackHandler handler;
    private MessageInfo messageInfo; 
    private Subject clientSubject;
    private AuthParameters authParameters;
    
    public HttpMsgContext(CallbackHandler handler, MessageInfo messageInfo, Subject clientSubject) {
        this.handler = handler;
        this.messageInfo = messageInfo;
        this.clientSubject = clientSubject;
        this.authParameters = Jaspic.getAuthParameters(getRequest());       
    }

    /**
     * Checks if the current request is to a protected resource or not. A protected resource
     * is a resource (e.g. a Servlet, JSF page, JSP page etc) for which a constraint has been defined
     * in e.g. <code>web.xml<code>.
     * 
     * @return true if a protected resource was requested, false if a public resource was requested.
     */
    public boolean isProtected() {
        return Jaspic.isProtectedResource(messageInfo);
    }
    
    /**
     * Asks the container to register the given username and roles in order to make
     * them available to the application for use with {@link HttpServletRequest#isUserInRole(String)} etc.
     * <p>
     * This will also ask the runtime to register an authentication session that will live as long as the
     * HTTP session is valid. 
     * <p>
     * Note that after this call returned, the authenticated identity will not be immediately active. This
     * will only take place (should not errors occur) after the {@link ServerAuthContext} or {@link ServerAuthModule}
     * in which this call takes place return control back to the runtime.
     * 
     * @param username the user name that will become the caller principal
     * @param roles the roles associated with the caller principal
     */
    public void registerWithContainer(String username, List<String> roles) {
        registerWithContainer(username, roles, true);
    }
    
    /**
     * Asks the container to register the given username and roles in order to make
     * them available to the application for use with {@link HttpServletRequest#isUserInRole(String)} etc.
     * <p>
     * This will optionally (on the basis of the registerSession parameter) ask the runtime to register an 
     * authentication session that will live as long as the HTTP session is valid. 
     * <p>
     * Note that after this call returned, the authenticated identity will not be immediately active. This
     * will only take place (should not errors occur) after the {@link ServerAuthContext} or {@link ServerAuthModule}
     * in which this call takes place return control back to the runtime.
     * 
     * @param username the user name that will become the caller principal
     * @param roles the roles associated with the caller principal
     * @param registerSession if true asks the container to register an authentication setting, if false does not ask this.
     */
    public void registerWithContainer(String username, List<String> roles, boolean registerSession) {
        Jaspic.notifyContainerAboutLogin(clientSubject, handler, username, roles);
        if (registerSession) {
            Jaspic.setRegisterSession(messageInfo, username, roles);
        }
    }
    
    /**
     * Checks if during the current request code has asked the runtime to register an authentication session.
     * 
     * @return true if code has asked to register an authentication session, false otherwise.
     */
    public boolean isRegisterSession() {
        return Jaspic.isRegisterSession(messageInfo);
    }

    /**
     * Asks the runtime to register an authentication session. This will automatically remember the logged-in status
     * as long as the current HTTP session remains valid. Without this being asked, a SAM has to manually re-authenticate
     * with the runtime at the start of each request.
     * <p>
     * Note that the user name and roles being asked is an implementation detail; there is no portable way to have
     * an auth context read back the user name and roles that were processed by the {@link CallbackHandler}.
     * 
     * @param username the user name for which authentication should be be remembered
     * @param roles the roles for which authentication should be remembered.
     */
    public void setRegisterSession(String username, List<String> roles) {
        Jaspic.setRegisterSession(messageInfo, username, roles);
    }
    
    public void cleanClientSubject() {
        Jaspic.cleanSubject(clientSubject);
    }
    
    /**
     * Returns the parameters that were provided with the {@link Jaspic#authenticate(AuthParameters)} call.
     *  
     * @return the parameters that were provided with the {@link Jaspic#authenticate(AuthParameters)} call, or a default instance. Never null.
     */
    public AuthParameters getAuthParameters() {
    	return authParameters;
    }
    
    /**
     * Returns the handler that the runtime provided to auth context.
     * 
     * @return the handler that the runtime provided to auth context.
     */
    public CallbackHandler getHandler() {
        return handler;
    }

    /**
     * Returns the message info instance for the current request.
     * 
     * @return the message info instance for the current request.
     */
    public MessageInfo getMessageInfo() {
        return messageInfo;
    }

    /**
     * Returns the subject for which authentication is to take place.
     * 
     * @return the subject for which authentication is to take place.
     */
    public Subject getClientSubject() {
        return clientSubject;
    }
    
    /**
     * Returns the request object associated with the current request.
     * 
     * @return the request object associated with the current request.
     */
    public HttpServletRequest getRequest() {
        return (HttpServletRequest) messageInfo.getRequestMessage();
    }
    
    /**
     * Returns the response object associated with the current request.
     * 
     * @return the response object associated with the current request.
     */
    public HttpServletResponse getResponse() {
        return (HttpServletResponse) messageInfo.getResponseMessage();
    }

}