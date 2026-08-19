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
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class HttpServletRequestXssPolicyFilter extends OncePerRequestFilter {
	
	protected PolicyFactory DEFAULT_POLICY = new HtmlPolicyBuilder().toFactory();
	
	/**Xss检查策略工厂*/
	protected PolicyFactory policyFactory = DEFAULT_POLICY;
	/** 需要进行Xss检查的Header */
	protected String[] policyHeaders = null;

	/**
	 * do Filter Internal.
	 *
	 * @param request the request
	 * @param response the response
	 * @param filterChain the filter chain
	 * @throws ServletException if an error occurs
	 * @throws IOException if an error occurs
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		filterChain.doFilter(new HttpServletXssPolicyRequestWrapper(getPolicyFactory(), getPolicyHeaders(), request), response);
	}

	/**
	 * Returns the policy factory.
	 *
	 * @return the policy factory
	 */
	public PolicyFactory getPolicyFactory() {
		return policyFactory;
	}

	/**
	 * Sets the policy factory.
	 *
	 * @param policyFactory the policy factory
	 */
	public void setPolicyFactory(PolicyFactory policyFactory) {
		this.policyFactory = policyFactory;
	}

	/**
	 * Returns the policy headers.
	 *
	 * @return the policy headers
	 */
	public String[] getPolicyHeaders() {
		return policyHeaders;
	}

	/**
	 * Sets the policy headers.
	 *
	 * @param policyHeaders the policy headers
	 */
	public void setPolicyHeaders(String[] policyHeaders) {
		this.policyHeaders = policyHeaders;
	}
 
	
}
