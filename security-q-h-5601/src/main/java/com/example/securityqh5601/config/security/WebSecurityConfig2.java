package com.example.securityqh5601.config.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

//这个加不加无所谓
//@Configuration
//开启security自定义配置
@EnableWebSecurity
//开启 Controller层的访问方法权限，与注解@PreAuthorize("hasRole('ROLE_admin')")配合，会拦截注解了@PreAuthrize注解的配置
// 想要@PreAuthorize正确执行 ，权限关键字必须带前缀 ROLE_  ，后面的部分可以随便写！！！！靠，琢磨了4小时了 ，终于找到原因了
@EnableGlobalMethodSecurity(prePostEnabled = true)
//
public class WebSecurityConfig2 extends WebSecurityConfigurerAdapter {

    //实例自定义登录校验接口 【内部有 数据库查询】
    @Autowired
    private DbUserDetailsService2 dbUserDetailsService;

    //jwt认证拦截
    @Autowired
    private JWTFilter jwtFilter;

    /**
     * 忽略过滤的静态文件路径
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers(
                        "/js/**/*.js",
                        "/css/**/*.css",
                        "/img/**",
                        "/html/**/*.html"
                );
    }


    /**
     * 全局的跨域配置
     */
    @Bean
    public WebMvcConfigurer WebMvcConfigurer() {
        return new WebMvcConfigurer() {
            public void addCorsMappings(CorsRegistry corsRegistry) {
                //仅仅让/login可以跨域
                corsRegistry.addMapping("/login").allowCredentials(true).allowedHeaders("*");
                //仅仅让/logout可以跨域
                corsRegistry.addMapping("/logout").allowCredentials(true).allowedHeaders("*");
                //允许所有接口可以跨域访问
                //corsRegistry.addMapping("/**").allowCredentials(true).allowedHeaders("*");

            }
        };

    }


    //拦截规则设置
    @Override
    protected void configure(HttpSecurity http) throws Exception {


        //开启授权认证
        //开启跨域共享，关闭同源策略【允许跨域】
        http.cors()
                //跨域伪造请求=无效，
                .and().csrf().disable();


        //配置路径拦截规则
        http.authorizeRequests()
//        只要有 "user","admin"任意最少一个权限即可访问路径"/user/**"的所有接口
//                .antMatchers("/user/**").hasAnyAuthority("ROLE_user", "ROLE_admin")
//                //只有权限"admin"才可以访问"/admin/**"所有路径 和 接口 "/vip"
//                .antMatchers("/admin/**", "/vip").hasAuthority("ROLE_admin")
                //所有请求都需要验证,必须要放在antMatchers路径拦截之后，不然拦截失效
                .anyRequest().authenticated();
        // //路径拦截权限的名称必须与权限列表注册的一样，经过测试，方法级别的注解权限需要ROLE_前缀 ，因此，
        // 路径拦截权限的名称、注解权限名称、数据库存储的权限名称都要加ROLE_前缀最好，避免出现错误，
        // 如果数据库的权限名称不加ROLE_前缀，那么在注册权限列表的时候记得拼接ROLE_前缀


        //登录配置
        http.formLogin()
                //定义登录名参数
                .usernameParameter("username")
                //定义密码参数
                .passwordParameter("password")
                //post登录访问路径
                .loginProcessingUrl("/login");

        //登录结果处理
        http.formLogin()
                //登录成功
                .successHandler(new CustomAuthenticationSuccessHandler())   //--0
                //登录失败
                .failureHandler(new CustomAuthenticationFailureHandler());  //--0

        //登录退出处理
        http.logout()
                ////post登出访问路径
                .logoutUrl("/logout")
                //成功退出处理
                .logoutSuccessHandler(new CustomLogoutSuccessHandler())   //--0
                //清除认证信息
                .clearAuthentication(true).permitAll();

        //异常抛出处理
        http.exceptionHandling().authenticationEntryPoint(new CustomAuthenticationEntryPoint())     //-- 401
                //访问拒绝处理【无权】
                .accessDeniedHandler(new CustomAccessDeniedHandler());          //--2

        //jwt登录拦截，需要在账户密码认证之前进行jwt认证，jwt通过则不需要执行用户密码拦截，但是会执行两次jwt拦截，原因不清楚，
        //如果jwt没有通过，将会执行用户密码拦截
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        //开启cookie自动登录
        http.rememberMe()
                //自动登录成功处理//todo
//                .authenticationSuccessHandler(new  ....)
                //密钥
                .key("unique-and-secret")
                //cookie名
                .rememberMeCookieName("remember-me-cookie-name")
                //生命周期，单位毫秒
                .tokenValiditySeconds(24 * 60 * 60);


        //session并发管理 ，原理是其缺省实现是将session记录在内存map中，因此不能用于集群环境中，服务器1中记录的信息和服务器2记录的信息并不相同；
        //
//        Session的并发控制,这里设为最多一个，只允许一个用户登录,如果同一个账户两次登录,那么第一个账户将被踢下线
//        http.sessionManagement().maximumSessions(1);
        //当一个用户已经认证过了，在另外一个地方重新进行登录认证，spring security可以阻止其再次登录认证，从而保持原来的会话可用性
        //存在一个问题，当用户登陆后，没有退出直接关闭浏览器，则再次打开浏览器时，此时浏览器的session若被删除的话，用户只能等到服务器的session过期后，才能再次登录。
//        http.sessionManagement().maximumSessions(1).maxSessionsPreventsLogin(true);
        //默认是开通session fixation防护的.因此可以不写,防护的原理为，每当用户认证过后，就会重新生成一个新的session，并抛弃旧的session
//        http.sessionManagement().sessionFixation().migrateSession();


        //解决不允许显示在iframe的问题
//        http.headers().frameOptions().disable();




    }


    /**
     * 添加 UserDetailsService， 实现自定义登录校验，数据库查询
     * //其实就相当于将数据放于内存，或者说是用来获取用户的这却信息到的
     *
     * //实际上并没写具体的密码对比指令，是使用内部默认的
     *
     */
    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
        //注入用户信息，每次登录都会来这查询一次信息，因此不建议每次都向mysql查询，应该使用redis
        builder.userDetailsService(dbUserDetailsService)
                //密码加密方式
                .passwordEncoder(passwordEncoder());
    }

    /**
     * BCryptPasswordEncoder相关知识：
     * 用户表的密码通常使用MD5等不可逆算法加密后存储，为防止彩虹表破解更会先使用一个特定的字符串（如域名）加密，然后再使用一个随机的salt（盐值）加密。
     * 特定字符串是程序代码中固定的，salt是每个密码单独随机，一般给用户表加一个字段单独存储，比较麻烦。
     * BCrypt算法将salt随机并混入最终加密后的密码，验证时也无需单独提供之前的salt，从而无需单独处理salt问题。
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

//参考 博文原址
//https://www.dazhuanlan.com/2019/10/01/5d92e281abbc4/
//https://www.cnblogs.com/guos/archive/2019/10/02/11617243.html
//https://blog.csdn.net/icarusliu/article/details/78722384
//真想哭