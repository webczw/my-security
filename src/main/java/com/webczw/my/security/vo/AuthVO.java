package com.webczw.my.security.vo;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Set;

@Getter
@Setter
public class AuthVO {
    private List<String> role;
    private Set<String> permission;
    private String key;
    private String token;
    private Long expire;
}
