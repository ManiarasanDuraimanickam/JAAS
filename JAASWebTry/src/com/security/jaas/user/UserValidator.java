package com.security.jaas.user;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

public class UserValidator implements LoginModule {

	private CallbackHandler handler;
    private Subject subject;
    private UserPrincipal userPrincipal;
    private RolePrincipal rolePrincipal;
    private List<String> userGroups;
    private Map options;
    private Map sharedState;
    private boolean debug = false;
    private String username = null;
    private String password = null;
 
    private boolean isAuthenticated = false;
    private boolean commitSucceeded = false;
    private static final Logger logger = Logger.getLogger(UserValidator.class.getName());
    
	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		// TODO Auto-generated method stub
		// Store the handler
        this.handler = callbackHandler;
 
        // Subject reference holds the principals
        this.subject = subject;
 
        this.options = options;
        this.sharedState = sharedState;
 
        // Setup a logging class / state
        if ("true".equalsIgnoreCase((String) options.get("debug"))) {
            ConsoleHandler consoleHandler = new ConsoleHandler();
            logger.addHandler(consoleHandler);
            debug = true;
        }
		
	}

	@Override
	public boolean login() throws LoginException {
		 // If no handler is specified throw a error
        if (handler == null) {
            throw new LoginException("Error: no CallbackHandler available to recieve authentication information from the user");
        }
 
        // Declare the callbacks based on the JAAS spec
        Callback[] callbacks = new Callback[2];
        callbacks[0] = new NameCallback("login");
        callbacks[1] = new PasswordCallback("password", true);
 
        try {
 
            //Handle the callback and recieve the sent inforamation
            handler.handle(callbacks);
            username = ((NameCallback) callbacks[0]).getName();
            password = String.valueOf(((PasswordCallback) callbacks[1]).getPassword());
 
            // Debug the username / password
            if (debug) {
                logger.log(Level.INFO, "Username: {0}", username);
                logger.log(Level.INFO, "Password: {0}", password);
            }
 
            // We should never allow empty strings to be passed
            if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
                throw new LoginException("Data specified had null values");
            }
 
            // Validate against our database or any other options (this check is a example only)
            if (username != null && password != null) {
 
                // Assign the user roles
                userGroups = this.getRoles();
                isAuthenticated = true;
 
                return true;
            }
 
            throw new LoginException("Authentication failed");
 
        } catch (IOException | UnsupportedCallbackException e) {
            throw new LoginException(e.getMessage());
        }
 
	}

	@Override
	public boolean commit() throws LoginException {
		if (!isAuthenticated) {
            return false;
        } else {
 
            userPrincipal = new UserPrincipal(username);
            subject.getPrincipals().add(userPrincipal);
 
            if (userGroups != null && userGroups.size() > 0) {
                for (String groupName : userGroups) {
                    rolePrincipal = new RolePrincipal(groupName);
                    subject.getPrincipals().add(rolePrincipal);
                }
            }
 
            commitSucceeded = true;
 
            return true;
        }
	}

	@Override
	public boolean abort() throws LoginException {
		if (!isAuthenticated) {
            return false;
        } else if (isAuthenticated && !commitSucceeded) {
            isAuthenticated = false;
            username = null;
            password = null;
            userPrincipal = null;
        } else {
            logout();
        }
        return true;
	}

	@Override
	public boolean logout() throws LoginException {
		isAuthenticated = false;
        isAuthenticated = commitSucceeded;
        subject.getPrincipals().clear();
        return true;
	}
	
	private List<String> getRoles() {
		 
        List<String> roleList = new ArrayList<>();
        roleList.add("admin1");
 
        return roleList;
    }

}
