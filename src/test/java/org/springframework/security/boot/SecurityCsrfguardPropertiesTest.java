package org.springframework.security.boot;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.boot.csrfguard.CsrfguardJavascriptServletProperties;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SecurityCsrfguardProperties Tests")
class SecurityCsrfguardPropertiesTest {

    @Test
    @DisplayName("Default values are correct")
    void testDefaults() {
        SecurityCsrfguardProperties props = new SecurityCsrfguardProperties();
        assertThat(props.isEnabled()).isFalse();
        assertThat(props.getJavascript()).isNotNull();
        assertThat(props.getTokenName()).isEqualTo("OWASP_CSRFGUARD");
        assertThat(props.getTokenLength()).isEqualTo(32);
    }

    @Test
    @DisplayName("toProperties returns non-empty Properties")
    void testToProperties() {
        SecurityCsrfguardProperties props = new SecurityCsrfguardProperties();
        props.setNewTokenLandingPage("/landing");
        props.getJavascript().setSourceFile("/csrfguard.js");
        var properties = props.toProperties();
        assertThat(properties).isNotEmpty();
        assertThat(properties.containsKey("org.owasp.csrfguard.Enabled")).isTrue();
        assertThat(properties.containsKey("org.owasp.csrfguard.TokenName")).isTrue();
    }

    @Test
    @DisplayName("PREFIX constant")
    void testPrefix() {
        assertThat(SecurityCsrfguardProperties.PREFIX).isEqualTo("spring.security.csrf-guard");
    }

    @Test
    @DisplayName("Getters and setters work")
    void testGettersSetters() {
        SecurityCsrfguardProperties props = new SecurityCsrfguardProperties();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
        CsrfguardJavascriptServletProperties js = new CsrfguardJavascriptServletProperties();
        props.setJavascript(js);
        assertThat(props.getJavascript()).isSameAs(js);
    }
}
