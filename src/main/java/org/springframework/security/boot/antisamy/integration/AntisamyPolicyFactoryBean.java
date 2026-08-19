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
package org.springframework.security.boot.antisamy.integration;

import org.owasp.validator.html.Policy;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.util.ResourceUtils;
/**
 * AntisamyPolicyFactoryBean.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */

public class AntisamyPolicyFactoryBean implements FactoryBean<Policy>{

	/**
	 * policyconfiguration文件path
	 */
	private String policyConfigFilePath;
	
	/**
	 * Returns the object.
	 *
	 * @return the object
	 * @throws Exception if an error occurs
	 */
	@Override
	public Policy getObject() throws Exception {
		return Policy.getInstance(ResourceUtils.getFile(policyConfigFilePath));
	}

	/**
	 * Returns the object type.
	 *
	 * @return the object type
	 */
	@Override
	public Class<?> getObjectType() {
		return Policy.class;
	}

	/**
	 * Returns the singleton.
	 *
	 * @return the singleton
	 */
	@Override
	public boolean isSingleton() {
		return true;
	}

	/**
	 * Returns the policy config file path.
	 *
	 * @return the policy config file path
	 */
	public String getPolicyConfigFilePath() {
		return policyConfigFilePath;
	}

	/**
	 * Sets the policy config file path.
	 *
	 * @param policyConfigFilePath the policy config file path
	 */
	public void setPolicyConfigFilePath(String policyConfigFilePath) {
		this.policyConfigFilePath = policyConfigFilePath;
	}

	
}
