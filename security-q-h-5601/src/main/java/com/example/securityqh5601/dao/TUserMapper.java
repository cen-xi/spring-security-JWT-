package com.example.securityqh5601.dao;

import com.example.securityqh5601.entitis.tables.TUser;

import java.util.List;

public interface TUserMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(TUser record);

    int insertSelective(TUser record);

    TUser selectByPrimaryKey(Integer id);

    int updateByPrimaryKeySelective(TUser record);

    int updateByPrimaryKey(TUser record);

    //根据用户名获取信息
    TUser selectByUsername(String name);

    //获取所有信息
    List<TUser> selectAll();

}