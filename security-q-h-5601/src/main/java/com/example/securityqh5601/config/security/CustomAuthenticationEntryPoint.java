package com.example.securityqh5601.config.security;

import com.alibaba.fastjson.JSON;
import com.example.securityqh5601.config.security.bean.WebResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 认证入口（未登录状态）登录超时或者未登录的异常处理器
 */
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {


        WebResponse response = new WebResponse();
        response.setCode(String.valueOf(HttpServletResponse.SC_UNAUTHORIZED));
        System.out.println("authenticate fail,认证抛出异常，认证入口（未登录状态）");
        response.setMessage("authenticate fail,认证抛出异常，认证入口（未登录状态）");
        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
        httpServletResponse.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        httpServletResponse.getWriter().write(JSON.toJSONString(response));
    }
}
