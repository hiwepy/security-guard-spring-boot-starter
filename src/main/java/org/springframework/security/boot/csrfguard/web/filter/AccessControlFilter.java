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
 * @author [@Loong Wan](https://github.com/loong10k)
 * @since 1.0.0
 */
public abstract class AccessControlFilter implements Filter {

    protected FilterConfig filterConfig;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;
    }

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

    @Override
    public void destroy() {
    }

    protected abstract boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
            throws Exception;

    protected abstract boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception;
}
