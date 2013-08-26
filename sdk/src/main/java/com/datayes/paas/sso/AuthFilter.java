package com.datayes.paas.sso;

import javax.servlet.*;
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

    public void init(FilterConfig config) throws ServletException {
        String authUrl = config.getInitParameter("authUrl");
        String consumerUrl = config.getInitParameter("consumerUrl");
        System.out.println(consumerUrl);
        consumer = new Consumer(authUrl, consumerUrl);
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;
        String user = (String) request.getSession().getAttribute(USER);
        boolean isConsumerRequest = request.getRequestURL().toString().equals(consumer.getConsumerUrl());
        boolean isPost = "POST".equals(request.getMethod());
        boolean isGet = "GET".equals(request.getMethod());
        String responseMessage = request.getParameter("SAMLResponse");
        String consumerRequest = request.getParameter("SAMLRequest");
        if (isConsumerRequest) {
            if (user == null) {
                if (isPost) {
                    if (responseMessage != null) {
                        String relayState = request.getParameter("RelayState");
                        Map<String, String> result = consumer.processResponseMessage(responseMessage);
                        if (result != null) {
                            request.getSession().setAttribute(USER, result.get("Subject"));
                            response.sendRedirect(relayState);
                        } else {
                            invalidRequest(response);
                        }
                    } else if (consumerRequest != null) {
                        doLogout(request, consumerRequest);
                    } else {
                        invalidRequest(response);
                    }
                } else {
                    invalidRequest(response);
                }
            } else {
                if (isGet && request.getParameter("logout") != null) {
                    toLogout(request);
                } else {
                    invalidRequest(response);
                }
            }
            return;
        } else {
            if (user == null) {
                toAuth(request, response);
            } else {
                chain.doFilter(request, response);
            }
        }
    }

    private void invalidRequest(HttpServletResponse response) throws IOException {
        response.sendError(405, "invalid consumer request");
    }

    private void toLogout(HttpServletRequest request) throws IOException {
        consumer.buildRequestMessage(request);
        request.getSession().removeAttribute(USER);
    }

    private void doLogout(HttpServletRequest request, String consumerRequest) {
        Map<String, String> result = consumer.processRequestMessage(consumerRequest);
        if (result != null)
            request.getSession().removeAttribute(USER);


    }

    private void toAuth(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = consumer.buildRequestMessage(request);
        response.sendRedirect(url);
    }

    public void destroy() {
    }
}
