package com.webczw.my.security.service.impl;

import com.webczw.my.security.service.MyUserDetailServer;
import com.webczw.my.security.vo.SecurityUserVO;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class MyUserDetailServerImpl implements MyUserDetailServer {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        SecurityUserVO userVO = new SecurityUserVO();
        userVO.setUsername(username);
        // 正常需要根据用户名称去数据库查询用户密码
        userVO.setPassword(encoder.encode("123456"));
        userVO.setId(94034344000236L);
        userVO.setStatus(0);

        List<GrantedAuthority> list = new ArrayList<>();
        // 角色ROLE_作为前缀，权限点PER_作为前缀
        list.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        list.add(new SimpleGrantedAuthority("PER_ADD"));
        list.add(new SimpleGrantedAuthority("PER_UPDATE"));
        userVO.setAuthorities(list);
        return userVO;
    }
}
