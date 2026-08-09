package org.springframework.security.boot.sanitizer.web.filter;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.security.boot.sanitizer.web.servlet.http.HttpServletXssPolicyRequestWrapper;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * XSS(Cross Site Scripting)，即跨站脚本攻击request过滤
 * @author [@Loong Wan](https://github.com/loong10k)
 */
public class HttpServletRequestXssPolicyFilter extends OncePerRequestFilter {
	
	protected PolicyFactory DEFAULT_POLICY = new HtmlPolicyBuilder().toFactory();
	
	/**Xss检查策略工厂*/
	protected PolicyFactory policyFactory = DEFAULT_POLICY;
	/** 需要进行Xss检查的Header */
	protected String[] policyHeaders = null;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		filterChain.doFilter(new HttpServletXssPolicyRequestWrapper(getPolicyFactory(), getPolicyHeaders(), request), response);
	}

	public PolicyFactory getPolicyFactory() {
		return policyFactory;
	}

	public void setPolicyFactory(PolicyFactory policyFactory) {
		this.policyFactory = policyFactory;
	}

	public String[] getPolicyHeaders() {
		return policyHeaders;
	}

	public void setPolicyHeaders(String[] policyHeaders) {
		this.policyHeaders = policyHeaders;
	}
 
	
}
