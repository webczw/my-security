package com.webczw.my.security.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ResEnum {
    FORBIDDEN(1,"forBidden"),
    SUCCESS(2,"success"),
    UNAUTHORIZED(3,"unAuthorized"),
    FAIL(4,"fail");
    private Integer code;
    private String msg;
}
