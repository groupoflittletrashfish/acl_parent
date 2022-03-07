package com.atguigu.security.security;

import com.atguigu.servicebase.utils.R;
import com.atguigu.servicebase.utils.ResponseUtil;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author ：liwuming
 * @date ：Created in 2022/3/4 9:45
 * @description ：退出登录处理器
 * @modified By：
 * @version: 1.0
 */

@AllArgsConstructor
@NoArgsConstructor
public class TokenLogoutHandler implements LogoutHandler {

    private TokenManager tokenManage;
    private RedisTemplate redisTemplate;

    @Override
    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {
        //从Header中获取Token
        String token = httpServletRequest.getHeader("token");
        //Token不为空，移除Token,从Redis移除
        if (token != null) {
            //移除Token
            tokenManage.removeToken(token);
            //从Token中获取用户名
            String username = tokenManage.getUserInfoFromToken(token);
            //从Redis中移除Token
            redisTemplate.delete(username);
        }
        //返回成功提示
        ResponseUtil.out(httpServletResponse, R.ok());
    }
}
