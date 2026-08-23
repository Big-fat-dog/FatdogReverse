package com.fatdog.reverse;

import java.security.MessageDigest;

// L39 的被 Hook 目标
public class XpVerifier {

    // 正确 deviceId 的 SHA256（jadx 可见，但需要反查原值）
    private static final String EXPECTED_HASH = sha256("fatdog_xp_2026");

    public static boolean verifyDevice(String deviceId) {
        return sha256(deviceId).equals(EXPECTED_HASH);
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
