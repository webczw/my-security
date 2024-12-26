package com.webczw.my.security.service;

import com.webczw.my.security.vo.UserVO;

import java.util.List;

public interface IUserService {
    List<UserVO> findUserListById(Long userId);
}
