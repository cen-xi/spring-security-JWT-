package com.example.securityqh5601.controller;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
public class GGCo {

    //获取用户权限信息
    @RequestMapping({"/info"})
    //开启跨域
    // [普通跨域]
//    @CrossOrigin
    //[spring security 跨域]
//    @CrossOrigin(allowCredentials="true",allowedHeaders="*")
    @ResponseBody
    public Object info(@AuthenticationPrincipal Principal principal, HttpServletResponse response) {
        /**
         * 使用响应头信息的方式只能解决非security的工程，如果使用注解还需要声明资格和头信息，否则需要去security配置某一路径的的跨域资格和头信息
         */
        //跨域设置，如果是MVC 则可以 使用这个设置跨域
        response.setHeader("Access-Control-Allow-Origin", "*");
        //缓存控制 ： 不缓存
        response.setHeader("Cache-Control", "no-cache");
        return principal;
    }
}
