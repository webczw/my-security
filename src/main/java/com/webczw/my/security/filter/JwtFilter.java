package com.webczw.my.security.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.webczw.my.security.constant.Constants;
import com.webczw.my.security.utils.JwtUtils;
import com.webczw.my.security.vo.SecurityUserVO;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.rmi.ServerException;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Resource
    private JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 实现过滤逻辑
        String authorization = request.getHeader(Constants.TOKEN_KEY);
        System.out.println(authorization);
        if (authorization != null && authorization.startsWith(Constants.TOKEN_BEARER)) {
            // 验证JWT并设置用户信息到SecurityContextHolder中
            DecodedJWT jwt = jwtUtils.resolveToken(authorization);
            if (jwt != null) {
                Long uid = jwtUtils.getUid(jwt);
                SecurityUserVO details = jwtUtils.getUserDetails(jwt);
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(details, null, details.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                request.setAttribute("uid", uid);
            }
        }
        filterChain.doFilter(request, response);
    }

    public void validate(HttpServletRequest request) throws ServerException {
        //请求中传来的验证码
        String code = request.getParameter("code");
        String sessionCode = request.getSession().getAttribute("session_code").toString();
        if (StringUtils.isEmpty(code)) {
            throw new ServerException("验证码不能为空！");
        }
        if (StringUtils.isEmpty(sessionCode)) {
            throw new ServerException("验证码已经失效！");
        }
        if (!sessionCode.equalsIgnoreCase(code)) {
            throw new ServerException("验证码输入错误！");
        }

    }
}
