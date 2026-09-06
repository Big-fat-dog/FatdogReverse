package com.fatdog.reverse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

// Frida 关卡 5 的 deviceId 素材：正确值按两段异或存放，MD5 指纹只做校验。
// 还原方法 deviceId() 可被静态分析沿组装链调出，也可用 Frida 直接观察。
public class PivotParts {
    // "pivot_" 的字节 ^ 0x3C
    private static final int[] DEV_A = {76, 85, 74, 83, 72, 99};
    // "device" 的字节 ^ 0x5A
    private static final int[] DEV_B = {62, 63, 44, 51, 57, 63};

    private PivotParts() {}

    /** 把异或分片还原成正确 deviceId；Frida 可直接调用观察。 */
    public static String deviceId() {
        return dec(DEV_A, 0x3C) + dec(DEV_B, 0x5A);
    }

    /** 还原结果的 MD5 指纹（与 Activity 中的提交校验一致）。 */
    public static String fingerprint() {
        return md5Hex(deviceId());
    }

    static String md5Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String dec(int[] a, int key) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ key);
        }
        return new String(out, StandardCharsets.UTF_8);
    }
}
