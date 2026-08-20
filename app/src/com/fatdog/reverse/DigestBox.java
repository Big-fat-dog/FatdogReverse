package com.fatdog.reverse;

import java.security.MessageDigest;

// 诱饵工具类：一把从未被使用的"盐"和一套摘要方法，没有任何调用者。
public class DigestBox {
    static final String FAKE_SALT = "decoy_salt_for_l15";

    static String fakeSha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest((s + FAKE_SALT).getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}