package com.example.securityqh5601;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
//设置mapper接口包位置
@MapperScan(basePackages = "com.example.securityqh5601.dao")
public class SecurityQH5601Application {

    public static void main(String[] args) {
        SpringApplication.run(SecurityQH5601Application.class, args);
    }

}
