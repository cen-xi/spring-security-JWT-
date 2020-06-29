package com.example.securityqh5601.service.serviceImpl;

import com.example.securityqh5601.dao.TUserMapper;
import com.example.securityqh5601.entitis.tables.TUser;
import com.example.securityqh5601.service.UserService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


import javax.annotation.Resource;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


@Service
public class UserServiceImpl implements UserService {

    @Resource
    private TUserMapper tUserMapper;

    //根据用户名获取用户信息
    @Override
    public TUser getByUsername(String useranme) {
        return tUserMapper.selectByUsername(useranme);
    }

    //添加新用户
    @Override
    public Map<String,Object> addUser(String username, String psw) {
        Map<String,Object> map = new HashMap<>();
        if (StringUtils.isBlank(username) || StringUtils.isBlank(psw))
        {
            map.put("data","参数不可空");
            return map;
        }

        ////根据用户名获取用户信息
        TUser u = tUserMapper.selectByUsername(username);
        if (u!= null){
            map.put("data","用户名已经存在");
            return map;
        }
        //
        TUser tUser = new TUser();
        tUser.setUsername(username);
        //
        //BCryptPasswordEncoder 单向加密
        tUser.setPsw((new BCryptPasswordEncoder()).encode(psw));
        //
        tUser.setNickname("别名-昵称");
        tUser.setRole("user");
        tUser.setSettime(new Date());
        int len = tUserMapper.insertSelective(tUser);
        if (len!=1){
            map.put("data","失败");
        }else {
            map.put("data","成功");
        }
        return map;
    }
}
