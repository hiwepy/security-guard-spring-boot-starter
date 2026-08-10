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
package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link SecurityXssPolicyProperties}.
 *
 * <p>Verifies default values, getters/setters and POJO contract.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@DisplayName("SecurityXssPolicyProperties Tests")
class SecurityXssPolicyPropertiesTest {
    @Test
    @DisplayName("Default constructor creates non-null instance")
    void testDefaultInstance() {
        SecurityXssPolicyProperties props = new SecurityXssPolicyProperties();
        assertThat(props).isNotNull();
    }

    @Test
    @DisplayName("Field 'enabled' can be set and read")
    void testEnabledField() {
        SecurityXssPolicyProperties props = new SecurityXssPolicyProperties();
        assertThat(props.isEnabled()).isFalse();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    @Test
    @DisplayName("Field 'policyHeaders' can be set and read")
    void testPolicyHeadersField() {
        SecurityXssPolicyProperties props = new SecurityXssPolicyProperties();
        String[] headers = {"X-XSS-Protection: 1; mode=block"};
        props.setPolicyHeaders(headers);
        assertThat(props.getPolicyHeaders()).isEqualTo(headers);
    }

    @Test
    @DisplayName("Public constant 'PREFIX' has expected value")
    void testPREFIXConstant() {
        assertThat(SecurityXssPolicyProperties.PREFIX).isEqualTo("spring.security.xss-policy");
    }
}
