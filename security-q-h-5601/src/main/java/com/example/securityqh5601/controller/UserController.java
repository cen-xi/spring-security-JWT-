package com.example.securityqh5601.controller;


import com.example.securityqh5601.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpSession;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class UserController {

//    @Autowired
//    private UserService userService;

//    //添加用户信息
//    @RequestMapping({"/addUser"})
//    public Map<String,Object> addUser(String username , String psw ) {
//        return userService.addUser(username,psw);
//    }

    //获取用户
    @RequestMapping("/getid/{id}")
    //开启跨域
    // [普通跨域]
    //@CrossOrigin
    //[spring security 跨域]
    @CrossOrigin(allowCredentials = "true", allowedHeaders = "*")
    @ResponseBody
    public Map<String, Object> getid(@PathVariable String id) {
        System.out.println("参数为==" + id);
        Map<String, Object> map = new HashMap<>();
        map.put("data", "参数为==" + id);
        return map;
    }

//    http://localhost:5601/getid/77

//=============================================================================
    /**
     * spring session 测试 专用
     */


    //当前主机的端口号
    @Value("${server.port}")
    Integer port;

    //向redis添加数据
    @GetMapping("/set")
    public String set(HttpSession session) {
        session.setAttribute("data", "shareData" + new Date());
        return String.valueOf(port);
    }

    //从redis获取数据
    @GetMapping("/get")
    public String get(HttpSession session) {
        return session.getAttribute("data") + "========================" + port;
    }



//    每个security 都需要登录一次用客户的信息，因此每个主机的session都会不同，
//    因此存储用户session的key可以是 session_用户名 ，数据共享
    //因此 从key值是唯一的 ，于是从redis获取的session数据也是唯一的，
    //每次登录都需要检查一下redis是否已经创建session，如果没有则创建，
    //这一步spring session 已经帮我们做好了，不需要管，将其视为单机session即可
    //这样不论在哪个boot里面服务，用户是唯一的
//==============================================================================================

}
