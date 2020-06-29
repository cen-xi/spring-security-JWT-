package com.example.securityqh5601.config.security;

import com.alibaba.fastjson.JSON;
import com.example.securityqh5601.config.security.bean.WebResponse;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        WebResponse response = WebResponse.success("登录成功,好爱你");
//        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
//        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
//        httpServletResponse.setCharacterEncoding(StandardCharsets.UTF_8.toString());
//        httpServletResponse.getWriter().write(JSON.toJSONString(response));
        //
        /**
         * 设置token
         */
        /*
        JWT方法：
         */
        //获取权限列表
        Collection<? extends GrantedAuthority> grantedAuthorities = authentication.getAuthorities();
        //拼接权限字符串，线程安全
        StringBuffer stringBuffer = new StringBuffer();
        for (GrantedAuthority grantedAuthority : grantedAuthorities) {
            System.out.println("当前有的权限：" + grantedAuthority);
            //用逗号隔开好一点，不然后面需要手动切割
            stringBuffer.append(grantedAuthority.getAuthority()).append(",");
        }
        //生成令牌 token
        String jwt = Jwts.builder()
                //登录角色的权限，这会导致如果权限更改，该token无法及时更新权限信息
                .claim("authorities", stringBuffer)
                //用户名
                .setSubject(authentication.getName())
                //存活时间，过期则判为无效，单位毫秒
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                //签名,第一个参数是算法，第二个参数是内容，内容可随意写，但是在解析的方法中，该字符串必须对应
                .signWith(SignatureAlgorithm.HS512, "java521@java")
                //协议完成
                .compact();
        System.out.println("令牌 token===" + jwt);
        //配置响应体
        Map<String, Object> map = new HashMap<>();
        map.put("msg", "登录成功");
        map.put("令牌token", jwt);


        //将信息返回前端
        //状态码 , 200
        httpServletResponse.setStatus(HttpServletResponse.SC_OK);
        //返回数据类型 ，json
        httpServletResponse.setContentType(MediaType.APPLICATION_JSON_VALUE);
        //返回字符解密方式
        httpServletResponse.setCharacterEncoding(StandardCharsets.UTF_8.toString());
        //返回的响应体
        httpServletResponse.getWriter().write(JSON.toJSONString(map));

    }
}
