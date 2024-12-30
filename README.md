# my-security

#### 介绍
Spring Boot 3.4.1 集成 Security


#### POM引入
```Xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```


#### 配置代码
```Java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
}
```

#### 配置信息
```properties
jwt.expire=50000
jwt.secret = OOS&34i$@#sT
```

#### 访问路径
[http://localhost:8080/my-security/login](http://localhost:8080/my-security/login)

