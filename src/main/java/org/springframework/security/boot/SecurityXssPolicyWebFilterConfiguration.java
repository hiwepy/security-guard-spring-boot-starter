package org.springframework.security.boot;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.sanitizer.web.filter.HttpServletRequestXssPolicyFilter;

/**
 * 默认拦截器
 */
@Configuration
@AutoConfigureBefore( name = {
	"org.apache.shiro.spring.config.web.autoconfigure.ShiroWebFilterConfiguration" // shiro-spring-boot-web-starter
})
@ConditionalOnWebApplication
@ConditionalOnClass({ PolicyFactory.class })
@ConditionalOnProperty(prefix = SecurityXssPolicyProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties(SecurityXssPolicyProperties.class)
public class SecurityXssPolicyWebFilterConfiguration {
	 
	@Bean
	@ConditionalOnMissingBean
	public PolicyFactory policyFactory() {
		return new HtmlPolicyBuilder().toFactory();
	}
	
	@Bean("xssPolicy")
	@ConditionalOnMissingBean(name = "xssPolicy")
	public FilterRegistrationBean<HttpServletRequestXssPolicyFilter> xssPolicyFilter(PolicyFactory policyFactory, SecurityXssPolicyProperties properties){
		FilterRegistrationBean<HttpServletRequestXssPolicyFilter> registration = new FilterRegistrationBean<HttpServletRequestXssPolicyFilter>();
		HttpServletRequestXssPolicyFilter xssPolicyFilter = new HttpServletRequestXssPolicyFilter();
		xssPolicyFilter.setPolicyFactory(policyFactory);
		xssPolicyFilter.setPolicyHeaders(properties.getPolicyHeaders());
		registration.setFilter(xssPolicyFilter);
	    registration.setEnabled(false); 
	    return registration;
	}

}
