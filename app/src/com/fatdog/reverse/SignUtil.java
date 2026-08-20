package com.fatdog.reverse;

import java.security.MessageDigest;

// Frida 关卡 4 的工具类之一：账号的 MD5 校验在这。
// 名字故意取成 SignUtil——教程里最常见的"签名工具类"名，让人以为它很普通。
public class SignUtil {
    static final String ACCOUNT_HASH = "c2fb08b69f270e9aae6e76438ec724a3";

    static boolean checkAccount(String account) {
        return md5Hex(account).equals(ACCOUNT_HASH);
    }

    static String md5Hex(String s) {
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