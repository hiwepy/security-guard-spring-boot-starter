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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Antisamy XSS(Cross Site Scripting)，即跨站脚本攻击请求过滤
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class HttpServletRequestAntisamyFilter extends OncePerRequestFilter {
	

	/** 路径解析工具 */
	protected UrlPathHelper urlPathHelper = new UrlPathHelper();
	/** 路径规则匹配工具 */
	protected PathMatcher pathMatcher = new AntPathMatcher();
	/** AntiSamy 对象缓存管理*/
	protected final AntiSamyCacheManager antiSamyCacheManager;
	/** Antisamy 配置 */
	protected final AntisamyProperties properties;
	
	public HttpServletRequestAntisamyFilter(AntiSamyCacheManager antiSamyCacheManager, AntisamyProperties properties) {
		this.antiSamyCacheManager = antiSamyCacheManager;
		this.properties = properties;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (this.matches(request)) {
			//根据请求获取响应的
			AntiSamyWrapper antiSamyWrapper = this.getAntiSamyWrapperForRequest(request);
			filterChain.doFilter(new HttpServletAntiSamyRequestWrapper(antiSamyWrapper, request), response);
		} else {
			filterChain.doFilter(request,response);
		}
		 
	}
	
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
	
	protected AntiSamyWrapper getAntiSamyWrapperForRequest(HttpServletRequest request) throws PolicyException {
		//解析请求路径
		String lookupPath = this.urlPathHelper.getLookupPathForRequest(request);
		for (String pattern : properties.getPolicyMappings().keySet()) {
			if (pathMatcher.match(pattern, lookupPath)) {
				String policy = properties.getPolicyMappings().get(pattern);
				return antiSamyCacheManager.getXssAntiSamyWrapper(policy, properties.getScanType(), properties.getPolicyHeaders());
			}
		}
		return antiSamyCacheManager.getDefaultAntiSamyWrapper(properties.getScanType(), properties.getPolicyHeaders());
	}
	
	@Override
	public void destroy() {
		super.destroy();
		antiSamyCacheManager.destroy();
	}


}
