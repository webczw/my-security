package com.webczw.my.security.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.webczw.my.security.constant.Constants;
import com.webczw.my.security.enums.ResEnum;
import com.webczw.my.security.filter.JwtFilter;
import com.webczw.my.security.service.impl.MyUserDetailServerImpl;
import com.webczw.my.security.utils.JwtUtils;
import com.webczw.my.security.vo.AuthVO;
import com.webczw.my.security.vo.SecurityUserVO;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Resource
    private JwtUtils jwtUtils;

    @Resource
    private JwtFilter jwtFilter;

    @Resource
    private MyUserDetailServerImpl myUserDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



    /*
     * 验证管理器
     * */
    @Bean
    public AuthenticationManager authenticationManager(PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//将编写的UserDetailsService注入进来
        provider.setUserDetailsService(myUserDetailsService);
//将使用的密码编译器加入进来
        provider.setPasswordEncoder(passwordEncoder);
//将provider放置到AuthenticationManager 中
        ProviderManager providerManager = new ProviderManager(provider);
        return providerManager;
    }

    private final String[] paths = {
            "/druid/**", "/system/captcha/line",
            "/druid/login.html/**","/login/**",
            "/system/login", "/js/**", "/*/*.json", "/*/*.yml",
            "/prims/**", "/type/**", "/system/file/**",
            "/diagram-viewer/**", "/images/**",
            "/api/login/**", "/api/file/**",
            "/css/**", "/*/*.ico", "/swagger-resources/**",
            "/swagger/**", "/swagger-ui/**",
            "/webjars/**", "/v3/**", "/v2/**", "/doc.html/**"
    };

    @Bean
    public SecurityFilterChain securityChain(HttpSecurity http) throws Exception {

        return http.authorizeHttpRequests(conf -> conf.requestMatchers(paths).permitAll()
                        .anyRequest().authenticated())
                .formLogin(conf ->
                        conf.loginProcessingUrl("/login")
                                .usernameParameter("username")
                                .passwordParameter("password")
                                .successHandler(this::onAuthenticationSuccess)
                                .failureHandler(this::onAuthenticationFailure))
                /*.exceptionHandling(conf ->
                        conf.authenticationEntryPoint(this::noLogin)
                                .accessDeniedHandler(this::noPermission))*/
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(conf -> conf.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();

    }


    private void noPermission(HttpServletRequest request,
                              HttpServletResponse response,
                              AccessDeniedException e) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        PrintWriter writer = response.getWriter();
        jsonWriter(writer, ResEnum.FORBIDDEN.getCode(), ResEnum.FORBIDDEN.getMsg());

    }

    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        SecurityUserVO user = (SecurityUserVO) authentication.getPrincipal();
        Long uid = user.getId();
        Set<String> permissions = new HashSet<>();
        for (GrantedAuthority authority : user.getAuthorities()) {
            String auth = authority.getAuthority();
            permissions.add(auth);
        }
        String token = jwtUtils.createToken(user, uid, user.getUsername(),user.getPassword());
        AuthVO authVo = new AuthVO();
        authVo.setRole(this.getUserRoles(uid));
        authVo.setPermission(permissions);
        authVo.setKey(Constants.TOKEN_KEY);
        authVo.setToken(token);
        authVo.setExpire(jwtUtils.expireTime().getTime());
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        PrintWriter writer = response.getWriter();
        jsonWriter(writer, ResEnum.SUCCESS.getCode(), ResEnum.SUCCESS.getMsg(), authVo);
    }

    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        PrintWriter writer = response.getWriter();
        jsonWriter(writer, ResEnum.UNAUTHORIZED.getCode(), exception.getMessage());
    }

    public void noLogin(HttpServletRequest request, HttpServletResponse response,
                        AuthenticationException authException) throws IOException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        PrintWriter writer = response.getWriter();
        jsonWriter(writer, ResEnum.UNAUTHORIZED.getCode(), ResEnum.UNAUTHORIZED.getMsg());
    }


    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException {
        String authorization = request.getHeader("Authorization");
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        PrintWriter writer = response.getWriter();
        // 登出时，删除redis中的token
        if (jwtUtils.invalidateToken(authorization)) {
            jsonWriter(writer, ResEnum.SUCCESS.getCode(), ResEnum.SUCCESS.getMsg());
        } else {
            jsonWriter(writer, ResEnum.FAIL.getCode(), ResEnum.FAIL.getMsg());
        }


    }

    private void jsonWriter(PrintWriter writer, Integer code, String message) {
        jsonWriter(writer, code, message, null);
    }

    private void jsonWriter(PrintWriter writer, Integer code, String message, Object data) {
        Map<String,Object> dataMap = new HashMap<>();
        dataMap.put("code",code);
        dataMap.put("message",message);
        dataMap.put("data",data);
        ObjectMapper objectMapper = new ObjectMapper();
        try {
            writer.write(objectMapper.writeValueAsString(dataMap));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }finally {
            writer.flush();
            writer.close();
        }
    }


    private List<Long> getRoleIds(Long uid) {
        Map<Long,List<Long>> roleList = new HashMap<>();
        roleList.put(10023L,Arrays.asList(4556L,6644L,6777L));
        roleList.put(45543L,Arrays.asList(8001L,8002L,8003L));
        return roleList.get(uid);
    }

    private List<String> getUserRoles(Long uid) {
        Map<Long,List<String>> roleList = new HashMap<>();
        roleList.put(94034344000236L,Arrays.asList("ROLE_PM","ROLE_TD","ROLE_ADMIN"));
        roleList.put(45543L,Arrays.asList("ROLE_PCM","ROLE_SE","ROLE_OD"));
        return roleList.get(uid);
    }

    private Set<String> getPermissions(List<Long> roleIds) {
        Set<String> all = new HashSet<>();
        for (Long id : roleIds) {
            List<String> permissions = getUserPermissions(id);
            all.addAll(permissions);
        }
        return all;
    }

    private List<String> getUserPermissions(Long rid) {
        Map<Long,List<String>> permissionList = new HashMap<>();
        permissionList.put(10023L,Arrays.asList("Delete","Create","Query"));
        permissionList.put(45543L,Arrays.asList("Query","Export"));
        return permissionList.get(rid);
    }
}
