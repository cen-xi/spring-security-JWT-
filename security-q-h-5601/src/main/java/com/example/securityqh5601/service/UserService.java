package com.example.securityqh5601.service;



import com.example.securityqh5601.entitis.tables.TUser;

import java.util.Map;

public interface UserService {

    //根据用户名获取信息
    TUser getByUsername(String useranme);

    //添加用户
    Map<String,Object> addUser(String username , String psw);

}
