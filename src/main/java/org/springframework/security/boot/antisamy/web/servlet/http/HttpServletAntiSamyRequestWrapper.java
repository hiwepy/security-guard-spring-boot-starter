package org.springframework.security.boot.antisamy.web.servlet.http;

import org.springframework.security.boot.antisamy.cache.AntiSamyWrapper;
import org.springframework.security.boot.antisamy.utils.AntiSamyScanUtils;
import org.springframework.security.boot.antisamy.utils.XssScanUtils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

/**
 * RichText XSS(Cross Site Scripting)，即跨站脚本攻击request过滤
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public class HttpServletAntiSamyRequestWrapper extends HttpServletRequestWrapper {

	private AntiSamyWrapper antiSamyWrapper = null;
	
	/**
	 * Constructs a new http servlet anti samy request wrapper instance.
	 *
	 * @param antiSamyWrapper the anti samy wrapper
	 * @param request the request
	 */
	public HttpServletAntiSamyRequestWrapper(AntiSamyWrapper antiSamyWrapper, HttpServletRequest request) {
		super(request);
		this.antiSamyWrapper = antiSamyWrapper;
	}
	
	/**
	 * Returns the parameter map.
	 *
	 * @return the parameter map
	 */
	@Override
	public Map<String, String[]> getParameterMap() {
		Map<String, String[]> request_map = super.getParameterMap();
		Iterator<Entry<String, String[]>> iterator = request_map.entrySet().iterator();
		while (iterator.hasNext()) {
			Entry<String, String[]> me = iterator.next();
			String[] values = (String[]) me.getValue();
			for (int i = 0; i < values.length; i++) {
				// /System.out.println(values[i]);
				values[i] = xssClean(values[i]);
			}
		}
		return request_map;
	}

	/**
	 * get Parameter Values.
	 *
	 * @param name the name
	 * @return the result
	 */
	@Override
	public String[] getParameterValues(String name) {
		String[] rawValues = super.getParameterValues(name);
		if (rawValues == null){
			return null;
		}
		String[] cleanedValues = new String[rawValues.length];
		for (int i = 0; i < rawValues.length; i++) {
			cleanedValues[i] = xssClean(rawValues[i]);
		}
		return cleanedValues;
	}

	/**
	 * get Parameter.
	 *
	 * @param name the name
	 * @return the result
	 */
	@Override
	public String getParameter(String name) {
		String str = super.getParameter(name);
		if (str == null){
			return null;
		}
		return xssClean(str);
	}

	/**
	 * get Headers.
	 *
	 * @param name the name
	 * @return the result
	 */
	@Override
	public Enumeration<String> getHeaders(String name) {
		if(XssScanUtils.isXssHeader(antiSamyWrapper.getPolicyHeaders(), name)){
			return new AntiSamyEnumeration( super.getHeaders(name), antiSamyWrapper);
		}
        return super.getHeaders(name);
    }
	
	/**
	 * get Header.
	 *
	 * @param name the name
	 * @return the result
	 */
	@Override
	public String getHeader(String name) {
		String value = super.getHeader(name);
		if (value == null){
			return null;
		}
		if(XssScanUtils.isXssHeader(antiSamyWrapper.getPolicyHeaders(), name)){
			return xssClean(value);
		}
		return value;
	}
	
	/**
	 * Returns the cookies.
	 *
	 * @return the cookies
	 */
	@Override
	public Cookie[] getCookies() {
		Cookie[] existingCookies = super.getCookies();
		if (existingCookies != null) {
			for (int i = 0; i < existingCookies.length; ++i) {
				Cookie cookie = existingCookies[i];
				cookie.setValue(xssClean(cookie.getValue()));
			}
		}
		return existingCookies;
	}

	/**
	 * Returns the query string.
	 *
	 * @return the query string
	 */
	@Override
	public String getQueryString() {
		return xssClean(super.getQueryString());
	}

	/**
	 * xss Clean.
	 *
	 * @param taintedHTML the tainted h t m l
	 * @return the result
	 */
	public String xssClean(String taintedHTML) {
		return AntiSamyScanUtils.xssClean(_getHttpServletRequest(), antiSamyWrapper, taintedHTML);
	}
	
	/**
	 * _get HTTP Servlet Request.
	 *
	 * @return the result
	 */
	protected HttpServletRequest _getHttpServletRequest() {
		 return (HttpServletRequest) super.getRequest();
    }

}
