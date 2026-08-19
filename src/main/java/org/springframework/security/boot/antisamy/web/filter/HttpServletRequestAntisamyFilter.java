package org.springframework.security.boot.antisamy.web.filter;

import org.apache.commons.lang3.ArrayUtils;
import org.owasp.validator.html.PolicyException;
import org.springframework.security.boot.antisamy.AntisamyProperties;
import org.springframework.security.boot.antisamy.cache.AntiSamyCacheManager;
import org.springframework.security.boot.antisamy.cache.AntiSamyWrapper;
import org.springframework.security.boot.antisamy.web.servlet.http.HttpServletAntiSamyRequestWrapper;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Antisamy XSS(Cross Site Scripting)，即跨站脚本攻击request过滤
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class HttpServletRequestAntisamyFilter extends OncePerRequestFilter {
	

	/** path解析工具 */
	protected UrlPathHelper urlPathHelper = new UrlPathHelper();
	/** path规则匹配工具 */
	protected PathMatcher pathMatcher = new AntPathMatcher();
	/** AntiSamy 对象cache管理*/
	protected final AntiSamyCacheManager antiSamyCacheManager;
	/** Antisamy configuration */
	protected final AntisamyProperties properties;
	
	/**
	 * Constructs a new http servlet request antisamy filter instance.
	 *
	 * @param antiSamyCacheManager the anti samy cache manager
	 * @param properties the properties
	 */
	public HttpServletRequestAntisamyFilter(AntiSamyCacheManager antiSamyCacheManager, AntisamyProperties properties) {
		this.antiSamyCacheManager = antiSamyCacheManager;
		this.properties = properties;
	}

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
		if (this.matches(request)) {
			try {
				AntiSamyWrapper antiSamyWrapper = this.getAntiSamyWrapperForRequest(request);
				filterChain.doFilter(new HttpServletAntiSamyRequestWrapper(antiSamyWrapper, request), response);
			} catch (PolicyException e) {
				throw new ServletException("AntiSamy policy error", e);
			}
		} else {
			filterChain.doFilter(request,response);
		}
	}
	
	/**
	 * Determines whether matches.
	 *
	 * @param request the request
	 * @return the result
	 */
	protected boolean matches(HttpServletRequest request) {
		String lookupPath = this.urlPathHelper.getLookupPathForRequest(request);
		return this.matches(lookupPath, this.pathMatcher);
	}
	
	/**
	 * Returns {@code true} if the interceptor applies to the given request path.
	 * @param lookupPath the current request path
	 * @param pathMatcher a path matcher for path pattern matching
	 */
	protected boolean matches(String lookupPath, PathMatcher pathMatcher) {
		PathMatcher pathMatcherToUse = pathMatcher == null ? this.pathMatcher : pathMatcher;
		if (ArrayUtils.isNotEmpty(properties.getExcludePatterns())) {
			for (String pattern : properties.getExcludePatterns()) {
				if (pathMatcherToUse.match(pattern, lookupPath)) {
					return false;
				}
			}
		}
		if (ArrayUtils.isEmpty(properties.getIncludePatterns())) {
			return true;
		}
		else {
			for (String pattern : properties.getIncludePatterns()) {
				if (pathMatcherToUse.match(pattern, lookupPath)) {
					return true;
				}
			}
			return false;
		}
	}
	
	/**
	 * get Anti Samy Wrapper For Request.
	 *
	 * @param request the request
	 * @return the result
	 * @throws PolicyException if an error occurs
	 */
	protected AntiSamyWrapper getAntiSamyWrapperForRequest(HttpServletRequest request) throws PolicyException {
		//解析requestpath
		String lookupPath = this.urlPathHelper.getLookupPathForRequest(request);
		for (String pattern : properties.getPolicyMappings().keySet()) {
			if (pathMatcher.match(pattern, lookupPath)) {
				String policy = properties.getPolicyMappings().get(pattern);
				return antiSamyCacheManager.getXssAntiSamyWrapper(policy, properties.getScanType(), properties.getPolicyHeaders());
			}
		}
		return antiSamyCacheManager.getDefaultAntiSamyWrapper(properties.getScanType(), properties.getPolicyHeaders());
	}
	
	/**
	 * destroy.
	 *
	 */
	@Override
	public void destroy() {
		super.destroy();
		antiSamyCacheManager.destroy();
	}


}
