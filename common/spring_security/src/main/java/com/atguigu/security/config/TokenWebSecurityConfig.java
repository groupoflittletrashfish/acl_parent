package com.atguigu.security.config;

import com.atguigu.security.filter.TokenAuthFilter;
import com.atguigu.security.filter.TokenLoginFilter;
import com.atguigu.security.security.DefaultPasswordEncoder;
import com.atguigu.security.security.TokenLogoutHandler;
import com.atguigu.security.security.TokenManager;
import com.atguigu.security.security.UnauthEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author ：liwuming
 * @date ：Created in 2022/3/4 11:26
 * @description ：Security核心配置类
 * @modified By：
 * @version: 1.0
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final TokenManager tokenManager;
    private final RedisTemplate redisTemplate;
    private final DefaultPasswordEncoder defaultPasswordEncoder;
    private final UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling()
                //指定授权失败过滤器，也就是权限不足的时候调用
                .authenticationEntryPoint(new UnauthEntryPoint())
                .and().csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                //指定退出登录的API路径
                .and().logout().logoutUrl("/admin/acl/index/logout")
                //指定退出登录处理器
                .addLogoutHandler(new TokenLogoutHandler(tokenManager, redisTemplate))
                .and()
                //指定认证过滤器
                .addFilter(new TokenLoginFilter(tokenManager, redisTemplate, authenticationManager()))
                //指定授权过滤器
                .addFilter(new TokenAuthFilter(tokenManager, redisTemplate, authenticationManager()));


    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //指定登录逻辑和加密方式
        auth.userDetailsService(userDetailsService).passwordEncoder(defaultPasswordEncoder);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //其实就和之前写的放行路径一样，没有区别，只是分开了更清楚一些
        web.ignoring().antMatchers("/api/**");
    }
}
