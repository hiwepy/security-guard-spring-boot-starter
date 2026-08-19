/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.csrfguard;

import org.apache.commons.collections4.MapUtils;

import java.util.*;

/**
 * TODO
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class CsrfguardProperties {

	private final static String ACTION_PREFIX = "org.owasp.csrfguard.action.";

	private final static String PROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.protected.";

	private final static String UNPROTECTED_PAGE_PREFIX = "org.owasp.csrfguard.unprotected.";

	public enum LoggerType {

		CONSOLE("org.owasp.csrfguard.log.ConsoleLogger"), 
		JAVA("org.owasp.csrfguard.log.JavaLogger");

		private final String implClassName;

		LoggerType(String implClassName) {
			this.implClassName = implClassName;
		}

		/**
		 * class Name.
		 *
		 * @return the result
		 */
		public String className() {
			return implClassName;
		}

		/**
		 * Determines whether equals.
		 *
		 * @param loggerType the logger type
		 * @return the result
		 */
		public boolean equals(LoggerType loggerType) {
			return this.compareTo(loggerType) == 0;
		}

	}

	private boolean enabled = false;
	private LoggerType logger = LoggerType.CONSOLE;
	private String tokenName = "OWASP_CSRFGUARD";
	private int tokenLength = 32;
	private boolean rotateEnabled = false;
	private boolean tokenPerPageEnabled = false;
	/**
	 * If csrf guard filter should check even if there is no session for the user
	 * Note: this changed in 2014/04, the default behavior used to be to not check
	 * if there is no session. If you want the legacy behavior (if your app is not
	 * susceptible to CSRF if the user has no session), set this to false
	 */
	private boolean validationWhenNoSessionExists = true;

	private boolean tokenPerPagePrecreateEnabled = false;
	private boolean printConfig = false;
	private String prng = "SHA1PRNG";
	private String prngProvider = "SUN";

	private String newTokenLandingPage;

	private boolean useNewTokenLandingPage = false;

	private boolean ajaxEnabled = false;

	private boolean protectEnabled = false;

	private String sessionKey = "OWASP_CSRFGUARD_KEY";

	private Map<String, String> actions = new HashMap<String, String>();

	private Map<String, String> protectedPages = new HashMap<String, String>();

	private Map<String, String> unprotectedPages = new HashMap<String, String>();

	private Set<String> protectedMethods = new HashSet<String>();

	private Set<String> unprotectedMethods = new HashSet<String>();

	/**
	 * Returns the enabled.
	 *
	 * @return the enabled
	 */
	public boolean isEnabled() {
		return enabled;
	}

	/**
	 * Sets the enabled.
	 *
	 * @param enabled the enabled
	 */
	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	/**
	 * Returns the logger.
	 *
	 * @return the logger
	 */
	public LoggerType getLogger() {
		return logger;
	}

	/**
	 * Sets the logger.
	 *
	 * @param logger the logger
	 */
	public void setLogger(LoggerType logger) {
		this.logger = logger;
	}

	/**
	 * Returns the token name.
	 *
	 * @return the token name
	 */
	public String getTokenName() {
		return tokenName;
	}

	/**
	 * Sets the token name.
	 *
	 * @param tokenName the token name
	 */
	public void setTokenName(String tokenName) {
		this.tokenName = tokenName;
	}

	/**
	 * Returns the token length.
	 *
	 * @return the token length
	 */
	public int getTokenLength() {
		return tokenLength;
	}

	/**
	 * Sets the token length.
	 *
	 * @param tokenLength the token length
	 */
	public void setTokenLength(int tokenLength) {
		this.tokenLength = tokenLength;
	}

	/**
	 * Returns the rotate enabled.
	 *
	 * @return the rotate enabled
	 */
	public boolean isRotateEnabled() {
		return rotateEnabled;
	}

	/**
	 * Sets the rotate enabled.
	 *
	 * @param rotateEnabled the rotate enabled
	 */
	public void setRotateEnabled(boolean rotateEnabled) {
		this.rotateEnabled = rotateEnabled;
	}

	/**
	 * Returns the token per page enabled.
	 *
	 * @return the token per page enabled
	 */
	public boolean isTokenPerPageEnabled() {
		return tokenPerPageEnabled;
	}

	/**
	 * Sets the token per page enabled.
	 *
	 * @param tokenPerPageEnabled the token per page enabled
	 */
	public void setTokenPerPageEnabled(boolean tokenPerPageEnabled) {
		this.tokenPerPageEnabled = tokenPerPageEnabled;
	}

	/**
	 * Returns the validation when no session exists.
	 *
	 * @return the validation when no session exists
	 */
	public boolean isValidationWhenNoSessionExists() {
		return validationWhenNoSessionExists;
	}

	/**
	 * Sets the validation when no session exists.
	 *
	 * @param validationWhenNoSessionExists the validation when no session exists
	 */
	public void setValidationWhenNoSessionExists(boolean validationWhenNoSessionExists) {
		this.validationWhenNoSessionExists = validationWhenNoSessionExists;
	}

	/**
	 * Returns the token per page precreate enabled.
	 *
	 * @return the token per page precreate enabled
	 */
	public boolean isTokenPerPagePrecreateEnabled() {
		return tokenPerPagePrecreateEnabled;
	}

	/**
	 * Sets the token per page precreate enabled.
	 *
	 * @param tokenPerPagePrecreateEnabled the token per page precreate enabled
	 */
	public void setTokenPerPagePrecreateEnabled(boolean tokenPerPagePrecreateEnabled) {
		this.tokenPerPagePrecreateEnabled = tokenPerPagePrecreateEnabled;
	}

	/**
	 * Returns the print config.
	 *
	 * @return the print config
	 */
	public boolean isPrintConfig() {
		return printConfig;
	}

	/**
	 * Sets the print config.
	 *
	 * @param printConfig the print config
	 */
	public void setPrintConfig(boolean printConfig) {
		this.printConfig = printConfig;
	}

	/**
	 * Returns the prng.
	 *
	 * @return the prng
	 */
	public String getPrng() {
		return prng;
	}

	/**
	 * Sets the prng.
	 *
	 * @param prng the prng
	 */
	public void setPrng(String prng) {
		this.prng = prng;
	}

	/**
	 * Returns the prng provider.
	 *
	 * @return the prng provider
	 */
	public String getPrngProvider() {
		return prngProvider;
	}

	/**
	 * Sets the prng provider.
	 *
	 * @param prngProvider the prng provider
	 */
	public void setPrngProvider(String prngProvider) {
		this.prngProvider = prngProvider;
	}

	/**
	 * Returns the new token landing page.
	 *
	 * @return the new token landing page
	 */
	public String getNewTokenLandingPage() {
		return newTokenLandingPage;
	}

	/**
	 * Sets the new token landing page.
	 *
	 * @param newTokenLandingPage the new token landing page
	 */
	public void setNewTokenLandingPage(String newTokenLandingPage) {
		this.newTokenLandingPage = newTokenLandingPage;
	}

	/**
	 * Returns the use new token landing page.
	 *
	 * @return the use new token landing page
	 */
	public boolean isUseNewTokenLandingPage() {
		return useNewTokenLandingPage;
	}

	/**
	 * Sets the use new token landing page.
	 *
	 * @param useNewTokenLandingPage the use new token landing page
	 */
	public void setUseNewTokenLandingPage(boolean useNewTokenLandingPage) {
		this.useNewTokenLandingPage = useNewTokenLandingPage;
	}

	/**
	 * Returns the ajax enabled.
	 *
	 * @return the ajax enabled
	 */
	public boolean isAjaxEnabled() {
		return ajaxEnabled;
	}

	/**
	 * Sets the ajax enabled.
	 *
	 * @param ajaxEnabled the ajax enabled
	 */
	public void setAjaxEnabled(boolean ajaxEnabled) {
		this.ajaxEnabled = ajaxEnabled;
	}

	/**
	 * Returns the protect enabled.
	 *
	 * @return the protect enabled
	 */
	public boolean isProtectEnabled() {
		return protectEnabled;
	}

	/**
	 * Sets the protect enabled.
	 *
	 * @param protectEnabled the protect enabled
	 */
	public void setProtectEnabled(boolean protectEnabled) {
		this.protectEnabled = protectEnabled;
	}

	/**
	 * Returns the session key.
	 *
	 * @return the session key
	 */
	public String getSessionKey() {
		return sessionKey;
	}

	/**
	 * Sets the session key.
	 *
	 * @param sessionKey the session key
	 */
	public void setSessionKey(String sessionKey) {
		this.sessionKey = sessionKey;
	}

	/**
	 * Returns the actions.
	 *
	 * @return the actions
	 */
	public Map<String, String> getActions() {
		return actions;
	}

	/**
	 * Sets the actions.
	 *
	 * @param actions the actions
	 */
	public void setActions(Map<String, String> actions) {
		this.actions = actions;
	}

	/**
	 * Returns the protected pages.
	 *
	 * @return the protected pages
	 */
	public Map<String, String> getProtectedPages() {
		return protectedPages;
	}

	/**
	 * Sets the protected pages.
	 *
	 * @param protectedPages the protected pages
	 */
	public void setProtectedPages(Map<String, String> protectedPages) {
		this.protectedPages = protectedPages;
	}

	/**
	 * Returns the unprotected pages.
	 *
	 * @return the unprotected pages
	 */
	public Map<String, String> getUnprotectedPages() {
		return unprotectedPages;
	}

	/**
	 * Sets the unprotected pages.
	 *
	 * @param unprotectedPages the unprotected pages
	 */
	public void setUnprotectedPages(Map<String, String> unprotectedPages) {
		this.unprotectedPages = unprotectedPages;
	}

	/**
	 * Returns the protected methods.
	 *
	 * @return the protected methods
	 */
	public Set<String> getProtectedMethods() {
		return protectedMethods;
	}

	/**
	 * Sets the protected methods.
	 *
	 * @param protectedMethods the protected methods
	 */
	public void setProtectedMethods(Set<String> protectedMethods) {
		this.protectedMethods = protectedMethods;
	}

	/**
	 * Returns the unprotected methods.
	 *
	 * @return the unprotected methods
	 */
	public Set<String> getUnprotectedMethods() {
		return unprotectedMethods;
	}

	/**
	 * Sets the unprotected methods.
	 *
	 * @param unprotectedMethods the unprotected methods
	 */
	public void setUnprotectedMethods(Set<String> unprotectedMethods) {
		this.unprotectedMethods = unprotectedMethods;
	}

	/**
	 * to Properties.
	 *
	 * @return the result
	 */
	public Properties toProperties() {

		Properties properties = new Properties();

		properties.put("org.owasp.csrfguard.Logger", logger.className());
		properties.put("org.owasp.csrfguard.TokenName", tokenName);
		properties.put("org.owasp.csrfguard.TokenLength", tokenLength);
		properties.put("org.owasp.csrfguard.Rotate", rotateEnabled);
		properties.put("org.owasp.csrfguard.TokenPerPage", tokenPerPageEnabled);
		properties.put("org.owasp.csrfguard.ValidateWhenNoSessionExists", validationWhenNoSessionExists);
		properties.put("org.owasp.csrfguard.TokenPerPagePrecreate", tokenPerPagePrecreateEnabled);
		properties.put("org.owasp.csrfguard.PRNG", prng);
		properties.put("org.owasp.csrfguard.PRNG.Provider", prngProvider);
		properties.put("org.owasp.csrfguard.NewTokenLandingPage", newTokenLandingPage);
		properties.put("org.owasp.csrfguard.Config.Print", printConfig);
		properties.put("org.owasp.csrfguard.Enabled", enabled);
		properties.put("org.owasp.csrfguard.UseNewTokenLandingPage", useNewTokenLandingPage);
		properties.put("org.owasp.csrfguard.SessionKey", sessionKey);
		properties.put("org.owasp.csrfguard.Ajax", ajaxEnabled);
		properties.put("org.owasp.csrfguard.Protect", protectEnabled);
		properties.put("org.owasp.csrfguard.ProtectedMethods", String.join(",", protectedMethods));
		properties.put("org.owasp.csrfguard.UnprotectedMethods", String.join(",", unprotectedMethods));
		
		if(MapUtils.isNotEmpty(actions)) {
			Iterator<String> ite = actions.keySet().iterator();
			while (ite.hasNext()) {
				String key = ite.next();
				properties.put(ACTION_PREFIX + key, actions.get(key));
			}
		}

		if(MapUtils.isNotEmpty(protectedPages)) {
			Iterator<String> ite = protectedPages.keySet().iterator();
			while (ite.hasNext()) {
				String key = ite.next();
				properties.put(PROTECTED_PAGE_PREFIX + key, protectedPages.get(key));
			}
		}
		
		if(MapUtils.isNotEmpty(unprotectedPages)) {
			Iterator<String> ite = unprotectedPages.keySet().iterator();
			while (ite.hasNext()) {
				String key = ite.next();
				properties.put(UNPROTECTED_PAGE_PREFIX + key, unprotectedPages.get(key));
			}
		}

		return properties;
	}

}
