package com.atguigu.security.security;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * @author ：liwuming
 * @date ：Created in 2022/3/4 9:31
 * @description ：自定义的token生成类
 * @modified By：
 * @version: 1.0
 */

@Component
public class TokenManager {

    /**
     * Token有效时间
     */
    private long tokenEcpiration = 24 * 60 * 60 * 1000;

    /**
     * 编码密钥
     */
    private String tokenSignKey = "123456";


    /**
     * 根据用户名生成token
     */
    public String createToken(String username) {
        return Jwts.builder().setSubject(username)
                //指定失效时间
                .setExpiration(new Date(System.currentTimeMillis() + tokenEcpiration))
                //指定加密方式，密钥，压缩算法
                .signWith(SignatureAlgorithm.HS512, tokenSignKey).compressWith(CompressionCodecs.GZIP).compact();
    }


    /**
     * 根据Token获取用户信息
     */
    public String getUserInfoFromToken(String token) {
        return Jwts.parser().setSigningKey(tokenSignKey).parseClaimsJws(token).getBody().getSubject();
    }


    /**
     * 删除Token
     */
    public void removeToken(String token) {

    }

}
