package com.nsm.jass.tryout;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class MyCallBackHandler implements CallbackHandler {

	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		LoginTester.LOG.info("handle");
		NameCallback nameCallback = (NameCallback) callbacks[0];
		PasswordCallback passwordCallback = (PasswordCallback) callbacks[1];
		nameCallback.getPrompt();
		nameCallback.setName(new BufferedReader(
				new InputStreamReader(System.in)).readLine());
		passwordCallback.getPrompt();
		passwordCallback.setPassword(new BufferedReader(new InputStreamReader(
				System.in)).readLine().toCharArray());
	}

}
