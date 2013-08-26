package com.datayes.paas.sso;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * User: changhai
 * Date: 13-8-21
 * Time: 下午5:22
 * DataYes
 */
public class AuthFilter implements Filter {

    public static final String USER = "user";
    private Consumer consumer;
    private boolean cookie;

    public void init(FilterConfig config) throws ServletException {
        String authUrl = config.getInitParameter("authUrl");
        String consumerUrl = config.getInitParameter("consumerUrl");
        cookie = config.getInitParameter("cookie") != null;
        consumer = new Consumer(authUrl, consumerUrl, cookie);
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        setSsoUser(request);
        boolean processed = consumer.process(request, response);
        if (processed) {
            SsoContext.removeUser();
            return;
        } else {
            chain.doFilter(request, response);
            SsoContext.removeUser();
        }
    }

    private void setSsoUser(HttpServletRequest request) {
        if (cookie) {
            Cookie[] cookies = request.getCookies();
            for (Cookie c : cookies) {
                if (USER.equals(c.getName())) {
                    User user = new User(c.getName());
                    SsoContext.setUser(user);
                }
            }
        } else {
            String name = (String) request.getSession().getAttribute(USER);
            if (name != null) {
                User user = new User(name);
                SsoContext.setUser(user);
            }
        }
    }

    public void destroy() {
    }
}
