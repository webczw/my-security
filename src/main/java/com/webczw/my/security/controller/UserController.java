package com.webczw.my.security.controller;

import com.webczw.my.security.service.IUserService;
import com.webczw.my.security.vo.UserVO;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.annotation.Resource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/user")
@Tag(name = "user",description = "用户信息")
public class UserController {
    @Resource
    private IUserService userService;

    @GetMapping("/findUserListById/{userId}")
    @Operation(summary = "根据用户ID查询用户",description = "根据用户ID查询用户的详细信息集合")
    public List<UserVO> findUserListById(@Parameter(description = "用户ID") @PathVariable Long userId) {
        return userService.findUserListById(userId);
    }
}
