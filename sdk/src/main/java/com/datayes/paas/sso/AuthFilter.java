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
        String user = (String) request.getSession().getAttribute("user");
        boolean isConsumerRequest = request.getRequestURL().toString().equals(consumer.getConsumerUrl());
        boolean isPost = "POST".equals(request.getMethod());
        String responseMessage = request.getParameter("SAMLResponse");
        String consumerRequest = request.getParameter("SAMLRequest");
        if (user != null && !isConsumerRequest && !isPost) {
            chain.doFilter(request, response);
        } else {
            if (user == null && !isConsumerRequest) {
                toAuth(request, response);
            } else if (user == null && isConsumerRequest && isPost && responseMessage != null) {
                String relayState = request.getParameter("RelayState");
                Map<String, String> result = consumer.processResponseMessage(responseMessage);
                if (result != null) {
                    request.getSession().setAttribute("user", result.get("Subject"));
                    response.sendRedirect(relayState);
                }
            } else if (user != null && isConsumerRequest && !isPost) {
                toLogout(consumerRequest);
            } else if (user != null && isConsumerRequest && isPost && consumerRequest != null) {
                doLogout(consumerRequest);
            } else {
                System.out.println("invalid request");
            }
            return;
        }
    }

    private void toLogout(String consumerRequest) {
    }

    private void doLogout(String consumerRequest) {
    }

    private void toAuth(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = consumer.buildRequestMessage(request);
        response.sendRedirect(url);
    }

    public void destroy() {
    }
}
