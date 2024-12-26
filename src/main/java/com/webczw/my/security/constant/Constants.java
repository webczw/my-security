package com.webczw.my.security.constant;

public final class Constants {
    public static final String JWT_BLACK_LIST = "jwtBlackList";
    public static final String TOKEN_BEARER = "tokenBearer";
    public static final String TOKEN_KEY = "tokenKey";
    private Constants() {
        throw new AssertionError("No instances allowed");
    }
}
