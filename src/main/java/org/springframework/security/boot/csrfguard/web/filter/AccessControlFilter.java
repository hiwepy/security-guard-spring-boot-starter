package org.springframework.security.boot.csrfguard.web.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Abstract filter that provides access-control semantics similar to Shiro's
 * {@code AccessControlFilter}. Subclasses implement {@link #isAccessAllowed} and
 * {@link #onAccessDenied} to control request flow.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
public abstract class AccessControlFilter implements Filter {

    /**
     * init.
     *
     * @param filterConfig the filter config
     * @throws ServletException if an error occurs
     */
    protected FilterConfig filterConfig;

    /**
     * init.
     *
     * @param filterConfig the filter config
     * @throws ServletException if an error occurs
     */
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;
    }

    /**
     * do Filter.
     *
     * @param request the request
     * @param response the response
     * @param chain the chain
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        try {
            boolean allowed = isAccessAllowed(request, response, null);
            if (allowed) {
                chain.doFilter(request, response);
            } else {
                onAccessDenied(request, response);
            }
        } catch (IOException | ServletException e) {
            throw e;
        } catch (Exception e) {
            throw new ServletException("Access control filter error", e);
        }
    }

    /**
     * destroy.
     *
     */
    @Override
    public void destroy() {
    }

    /**
     * Determines whether is access allowed.
     *
     * @param request the request
     * @param response the response
     * @param mappedValue the mapped value
     * @return the result
     */
    protected abstract boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
            throws Exception;

    /**
     * Determines whether on access denied.
     *
     * @param request the request
     * @param response the response
     * @return the result
     * @throws Exception if an error occurs
     */
    protected abstract boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception;
}
