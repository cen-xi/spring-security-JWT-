package com.example.securityqh5601.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/admin")
public class AdminController {


    //获取用户权限信息
    @RequestMapping({"/info5"})
    //开启跨域
    @CrossOrigin(allowCredentials = "true", allowedHeaders = "*")
    //开启注解权限
    //必须有全部的权限才可以访问
//    @PreAuthorize("hasRole('ROLE_admin') and hasAnyRole('ROLE_user')")
    //至少有一个即可访问
//    @PreAuthorize("hasRole('ROLE_admin') or hasAnyRole('ROLE_user')")
    @PreAuthorize("hasAuthority('user')")
    @ResponseBody
    public Object info(@AuthenticationPrincipal Principal principal) {
        return principal;
    }
}
