package com.nsm.jass.tryout;

import java.io.IOException;
import java.util.Map;
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

public class LoginTester implements LoginModule {

	public static final Logger LOG = Logger.getGlobal();

	private CallbackHandler callBackHandler;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		LOG.info("initialize");
		this.callBackHandler = callbackHandler;
	}

	@Override
	public boolean login() throws LoginException {
		LOG.info("login");
		Callback[] callbacks = new Callback[2];
		callbacks[0] = new NameCallback("Username : ");
		callbacks[1] = new PasswordCallback("Password : ", false);
		try {
			this.callBackHandler.handle(callbacks);
			
			String username=((NameCallback)callbacks[0]).getName();
			String passwors=((PasswordCallback)callbacks[1]).getPassword().toString();
			LOG.info("Username "+username+" pass : "+passwors);
		} catch (IOException | UnsupportedCallbackException e) {
			LOG.log(Level.SEVERE, e.getMessage());
		}
		return true;
	}

	@Override
	public boolean commit() throws LoginException {
		LOG.info("commit");
		return true;
	}

	@Override
	public boolean abort() throws LoginException {
		LOG.info("abort");
		return false;
	}

	@Override
	public boolean logout() throws LoginException {
		LOG.info("logout");
		return false;
	}

}
