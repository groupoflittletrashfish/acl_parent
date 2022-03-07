package com.atguigu.security.security;

import com.atguigu.servicebase.utils.MD5;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * @author ：liwuming
 * @date ：Created in 2022/3/4 9:21
 * @description ：自定义的密码加密
 * @modified By：
 * @version: 1.0
 */
@Component
@NoArgsConstructor
public class DefaultPasswordEncoder implements PasswordEncoder {

    @Override
    public String encode(CharSequence charSequence) {
        return MD5.encrypt(charSequence.toString());
    }

    /**
     *
     * 检查密码是否匹配
     *
     */
    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return s.equals(MD5.encrypt(charSequence.toString()));
    }
}
