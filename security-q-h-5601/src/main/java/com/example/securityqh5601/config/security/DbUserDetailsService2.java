package com.example.securityqh5601.config.security;



import com.example.securityqh5601.entitis.tables.TUser;

import com.example.securityqh5601.service.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DbUserDetailsService2 implements UserDetailsService {

   @Autowired
   private UserService userService;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名查询用户信息
        TUser tUser = userService.getByUsername(username);
        if (tUser == null){
            throw new UsernameNotFoundException("用户不存在！");
        }
        //权限设置
        List<SimpleGrantedAuthority> simpleGrantedAuthorities = new ArrayList<>();
        String role = tUser.getRole();
        //分割权限名称，如 user,admin
        String[] roles = role.split(",");
        System.out.println("=============================");
        System.out.println("注册该账户权限");
        for (String r :roles){
            System.out.println(r);
            //添加权限
//            simpleGrantedAuthorities.add(new SimpleGrantedAuthority("ROLE_"+r));
            simpleGrantedAuthorities.add(new SimpleGrantedAuthority(r));
        }
        System.out.println("=============================");

        /**
         * 创建一个用于认证的用户对象并返回，包括：用户名，密码，角色
         */
        //输入参数
        return new org.springframework.security.core.userdetails.User(tUser.getUsername(), tUser.getPsw(), simpleGrantedAuthorities);
    }



}
