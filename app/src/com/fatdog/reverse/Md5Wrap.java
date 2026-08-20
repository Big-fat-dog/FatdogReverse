package com.fatdog.reverse;

import java.security.MessageDigest;

// 诱饵工具类：看起来像在做 MD5 校验，但整个类没有任何调用者。
public class Md5Wrap {
    static final String FAKE_HASH = "bdf89c84de9c7d8be6e7e4b2b8c2e1a5";

    static String fakeMd5(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}