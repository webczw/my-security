package com.webczw.my.security.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.webczw.my.security.constant.Constants;
import com.webczw.my.security.vo.SecurityUserVO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtUtils {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expire}")
    private Integer expire;

    private Map<String,String> redisMap = new HashMap<>();

    public Boolean invalidateToken(String haeadToken) {
        String token = convertToken(haeadToken);
        if (token == null) {
            return false;
        }
        try {
            DecodedJWT jwt = JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
            return deleteToken(jwt.getId(), jwt.getExpiresAt());
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    // 删除redis 中的Token
    private Boolean deleteToken(String id, Date date) {
        if (isInvalidToken(id)) {
            return false;
        }
        /*Date now = new Date();
        long expire = Math.max(date.getTime() - now.getTime(), 0);
        redisService.set(Prefix.JWT_BLACK_LIST + id, id, expire);*/
        redisMap.put(Constants.JWT_BLACK_LIST + id, id);
        return true;
    }

    // 验证 redis 中 token 是否存在
    private Boolean isInvalidToken(String id) {
        return Boolean.TRUE.equals(redisMap.containsKey(Constants.JWT_BLACK_LIST + id));
    }


    public String createToken(UserDetails details, Long id, String username, String password) {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        // redisService.set(Prefix.JWT_BLACK_LIST + id, id, expire);
        redisMap.put(Constants.JWT_BLACK_LIST + id, id.toString());
        return JWT.create().withJWTId(String.valueOf(id))
                .withClaim("id", id)
                .withClaim("username", username)
                .withClaim("password", password)
                .withClaim("authorities", getAuths(details))
                .withExpiresAt(expireTime())
                .sign(algorithm);
    }

    public String getAuths(UserDetails details) {
        return details.getAuthorities().stream().map(GrantedAuthority::getAuthority).
                collect(Collectors.joining(","));
    }

    // 获取过期时间
    public Date expireTime() {
        // 过期时间
        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.HOUR, expire * 24); // 默认7天
        return instance.getTime();
    }

    // 解析 JWT token
    public DecodedJWT resolveToken(String haeadToken) {
        String token = convertToken(haeadToken);
        if (token == null) {
            return null;
        }
        try {
            DecodedJWT jwt = JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
            if (isInvalidToken(jwt.getId())) {
                return null;
            }
            Date expires = jwt.getExpiresAt();
            return new Date().after(expires) ? null : jwt;
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    // 解析 截取真正有用的token
    private String convertToken(String haeadToken) {
        if (haeadToken == null || !haeadToken.startsWith(Constants.TOKEN_BEARER)) {
            return null;
        }
        return haeadToken.substring(7);
    }

    // 获取用户信息
    public SecurityUserVO getUserDetails(DecodedJWT jwt) {
        Map<String, Claim> claims = jwt.getClaims();
        String authorities = claims.get("authorities").asString();
        Set<SimpleGrantedAuthority> permissions = new HashSet<>();
        for (String auth : authorities.split(",")) {
            permissions.add(new SimpleGrantedAuthority(auth));
        }
        SecurityUserVO sysUser = new SecurityUserVO();
        sysUser.setId(jwt.getClaim("id").asLong());
        sysUser.setUsername(claims.get("username").toString());
        sysUser.setPassword(claims.get("password").toString());
        sysUser.setStatus(0);
        sysUser.setAuthorities(permissions);
        return sysUser;
    }

    // 获取用户ID
    public Long getUid(DecodedJWT jwt) {
        return jwt.getClaim("id").asLong();
    }
}
