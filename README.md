# my-security

#### 介绍
Spring Boot 3.4.1 集成 Swagger 3


#### POM引入
```Xml
<dependency>  
    <groupId>org.springdoc</groupId>  
    <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>  
    <version>2.0.4</version>  
</dependency>
```


#### 配置代码
```Java
@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI springOpenAPI() {
        return new OpenAPI().info(new Info()
                .title("SpringDoc API")
                .description("SpringDoc Simple Application")
                .version("0.0.1"));
    }
}
```

#### 配置信息
```properties
springdoc.swagger-ui.path=/index.html
```

#### 访问路径
[http://localhost:8080/my-security/swagger-ui/index.html](http://localhost:8080/my-security/swagger-ui/index.html)

