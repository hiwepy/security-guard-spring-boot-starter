package org.springframework.security.boot;

import org.springframework.security.boot.csrfguard.CsrfguardConstants;
import org.springframework.security.boot.csrfguard.CsrfguardJavascriptServletProperties;
import org.springframework.security.boot.csrfguard.web.filter.CsrfGuardFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * SecurityCsrfguardAutoConfiguration.
 * <p>Note: OWASP CSRFGuard's {@code JavaScriptServlet} and {@code CsrfGuardHttpSessionListener}
 * depend on {@code javax.servlet} and are therefore incompatible with Spring Boot 4.x
 * (which uses {@code jakarta.servlet}). The servlet and listener beans have been removed.</p>
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
@Configuration
@ConditionalOnProperty(prefix = SecurityCsrfguardProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties(SecurityCsrfguardProperties.class)
public class SecurityCsrfguardAutoConfiguration {

    /**
     * csrf Guard Filter.
     *
     * @return the result
     * @throws Exception if an error occurs
     */
	@Bean("csrf")
    @ConditionalOnMissingBean(name = "csrf")
    protected FilterRegistrationBean<CsrfGuardFilter> csrfGuardFilter() throws Exception {
        FilterRegistrationBean<CsrfGuardFilter> registration = new FilterRegistrationBean<CsrfGuardFilter>();
        registration.setFilter(new CsrfGuardFilter());
        registration.setOrder(Integer.MIN_VALUE);
        registration.setEnabled(false);
        return registration;
    }

}
