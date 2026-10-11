package com.fatdog.reverse.kkl5;

import java.security.MessageDigest;

/**
 * 诛仙台 · 业务片 5g —— 答案摘要。
 * 对总和字符串取 MD5（教学性：让玩家看清最终提交的是「和的摘要」）。
 */
public final class GateKeeper5g {

    private GateKeeper5g() {}

    public static String digest(long total) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] d = md.digest(GateKeeper5f.sumText(total).getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder(32);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
