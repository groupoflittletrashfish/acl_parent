package com.atguigu.security.filter;

import com.atguigu.security.entity.SecurityUser;
import com.atguigu.security.entity.User;
import com.atguigu.security.security.TokenManager;
import com.atguigu.servicebase.utils.R;
import com.atguigu.servicebase.utils.ResponseUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

/**
 * @author ：liwuming
 * @date ：Created in 2022/3/4 10:01
 * @description ：自定义登录过滤器
 * @modified By：
 * @version: 1.0
 */
public class TokenLoginFilter extends UsernamePasswordAuthenticationFilter {

    private TokenManager tokenManage;
    private RedisTemplate redisTemplate;
    private AuthenticationManager authenticationManager;

    /**
     * 有参构造，将传入的值赋值
     */
    public TokenLoginFilter(TokenManager tokenManage, RedisTemplate redisTemplate, AuthenticationManager authenticationManager) {
        this.tokenManage = tokenManage;
        this.redisTemplate = redisTemplate;
        this.authenticationManager = authenticationManager;
        //是否只能允许POST请求
        this.setPostOnly(false);
        //这个其实就是拦截的路径，也就是登录接口的路径，且限制为POST请求
        this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/admin/acl/login", "POST"));
    }

    /**
     * 主要是用于获取表单中的用户名和密码信息
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            //将Body对象映射成实体的对象，此处的USER是自定义的类
            User user = new ObjectMapper().readValue(request.getInputStream(), User.class);
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), new ArrayList<>()));
        } catch (IOException e) {
            e.printStackTrace();
            throw new RuntimeException();
        }
    }

    /**
     * 认证成功后触发
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        //认证成功，得到认证成功的用户信息
        SecurityUser user = (SecurityUser) authResult.getPrincipal();
        //根据用户名生成token
        String token = tokenManage.createToken(user.getCurrentUserInfo().getUsername());
        //将用户名称和用户权限列表放到redis中
        redisTemplate.opsForValue().set(user.getCurrentUserInfo().getUsername(), user.getPermissionValueList());

        ResponseUtil.out(response, R.ok().data("token", token));
    }


    /**
     * 认证失败后触发
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        ResponseUtil.out(response, R.error());
    }
}
