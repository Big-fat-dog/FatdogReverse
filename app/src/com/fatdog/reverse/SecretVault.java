package com.fatdog.reverse;

import java.security.MessageDigest;

// L40 探囊取物：明文只存在私有静态字段 s_hiddenKey 里，jadx 能看到的只有哈希。
// 模块用 XposedHelpers.getStaticObjectField 取出私钥后调用 reportStolenKey 回传，
// 哈希对上即记为"得手"，关卡自动判定通关（无需任何输入框）。
public class SecretVault {
    private static final String EXPECTED_HASH = sha256("Fatdog_xp40_secret");
    private static String s_hiddenKey = "Fatdog_xp40_secret";
    public static boolean stolen = false;
    private SecretVault() {}

    public static String getKey() { return s_hiddenKey; }

    public static boolean reportStolenKey(String taken) {
        if (taken != null && sha256(taken).equals(EXPECTED_HASH)) {
            stolen = true;
            return true;
        }
        return false;
    }

    static String sha256(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) { return ""; }
    }
}
