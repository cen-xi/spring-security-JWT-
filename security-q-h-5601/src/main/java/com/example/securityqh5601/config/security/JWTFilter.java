package com.example.securityqh5601.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;

/**
 * jwt登录拦截类 ---- 需要继承普通拦截bean
 */

@Component
public class JWTFilter extends GenericFilterBean {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        //强获取httpservletRequest类型
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        //从请求头获取数据
        //一般名称为 authorization，当然也可以修改，但需要与前端对应
        String tokenStr = httpServletRequest.getHeader("authorization");
        System.out.println("tokenStr数据是什么=="+tokenStr);
        if (!StringUtils.isBlank(tokenStr)){
            //用于判断是否解析成功
            boolean k = true;
            //令牌解析结果
            Jws<Claims> jws = null;
            //根据数字签名密钥解析令牌信息
            try{
                jws = Jwts.parser().setSigningKey("java521@java")
                        .parseClaimsJws(tokenStr.replace("Bearer", ""));
            }catch (Exception e){
                k = false;
            }
            if (k){
                // 令牌解析成功
                //令牌解析结果获取信息体
                Claims claims = jws.getBody();
                System.out.println("claims是什么"+claims);
                //获取token解析出来的用户名
                String username = claims.getSubject();
                System.out.println("获取token解析出来的用户名=="+username);
                //如果时以逗号格式配置字符串，可用以下方式解析,否则手动使用slipt解析
                //key值需要与加密时的权限key对应，就是个map类型
                List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList((String) claims.get("authorities"));
                System.out.println("所有权限"+grantedAuthorities);
                //new令牌登录校验 对象，参数分别是  ： 用户名 ，盐[没有则设为null] ，权限集合
                UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, null, grantedAuthorities);
                //执行令牌登录校验
                SecurityContextHolder.getContext().setAuthentication(token);
            }else {
                System.out.println("令牌解析失败");
                SecurityContextHolder.getContext()
                        .setAuthentication(new UsernamePasswordAuthenticationToken(null, null, null));
            }

        }else {
            //无令牌信息
            System.out.println("没有认证令牌");
            SecurityContextHolder.getContext()
                    .setAuthentication(new UsernamePasswordAuthenticationToken(null, null, null));
        }
        System.out.println("//让过滤器继续往下走，");
        //让过滤器继续往下走
       filterChain.doFilter(servletRequest,servletResponse);
    }
}
