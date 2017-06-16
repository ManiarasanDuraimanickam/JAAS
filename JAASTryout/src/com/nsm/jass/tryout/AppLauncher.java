package com.nsm.jass.tryout;

import java.util.logging.Level;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

public class AppLauncher {

	public static void main(String[] args) {
		LoginTester.LOG.info("Main");
		System.setProperty("java.security.auth.login.config",
				"SecurityContext.config");
		LoginContext context = null;
		try {
			context = new LoginContext("MyJASSLoginModule",
					new MyCallBackHandler());
		} catch (LoginException e) {
			LoginTester.LOG.log(Level.SEVERE,e.getMessage());
		}
		try {
			context.login();
		} catch (LoginException e) {
			LoginTester.LOG.log(Level.SEVERE,e.getMessage());
		}
	}
}
