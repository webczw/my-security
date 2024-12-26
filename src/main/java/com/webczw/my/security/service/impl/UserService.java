package com.webczw.my.security.service.impl;

import com.webczw.my.security.service.IUserService;
import com.webczw.my.security.vo.UserVO;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
public class UserService implements IUserService {
    @Override
    public List<UserVO> findUserListById(Long userId) {
        UserVO user1 = new UserVO();
        user1.setUserId(23400122L);
        user1.setUserName("张三");
        user1.setEntryDate(new Date());

        UserVO user2 = new UserVO();
        user2.setUserId(23500452L);
        user2.setUserName("李四");
        user2.setEntryDate(new Date());

        List<UserVO> userList = new ArrayList<>(2);
        userList.add(user1);
        userList.add(user2);
        return userList.stream().filter(vo -> Objects.equals(userId, vo.getUserId())).collect(Collectors.toList());
    }
}
