package br.com.damsete.security.cors;

import br.com.damsete.security.properties.SecurityProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorsFilter implements Filter {

    private final SecurityProperty securityProperty;

    @Autowired
    public CorsFilter(SecurityProperty securityProperty) {
        this.securityProperty = securityProperty;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain filterChain) throws IOException, ServletException {

        var request = (HttpServletRequest) servletRequest;
        var response = (HttpServletResponse) servletResponse;

        response.setHeader("Access-Control-Allow-Origin", this.securityProperty.getAllowOrigin());
        response.setHeader("Access-Control-Allow-Credentials", "true");

        if ("OPTIONS".equals(request.getMethod())) {
            response.setHeader("Access-Control-Allow-Methods", "POST, GET, DELETE, PUT, OPTIONS, HEAD, TRACE, CONNECT");
            response.setHeader(
                    "Access-Control-Allow-Headers", "Accept, Accept-Encoding, Accept-Language, " +
                            "Access-Control-Allow-Headers, Access-Control-Request-Headers, " +
                            "Access-Control-Request-Method, Authorization, Connection, Host, " +
                            "Origin, User-Agent, Access-Control-Allow-Origin, Content-Type, " +
                            "Content-Length, Date, X-Requested-With, Set-Cookie"
            );
            response.setHeader("Access-Control-Max-Age", "3600");

            response.setStatus(HttpServletResponse.SC_OK);
        } else {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }

    @Override
    public void destroy() {
        // not used
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // not used
    }
}
