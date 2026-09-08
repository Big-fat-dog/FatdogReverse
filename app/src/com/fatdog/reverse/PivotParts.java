package com.fatdog.reverse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

// Frida 关卡 5 的 deviceId 素材：正确值按两段异或存放，MD5 指纹只做校验。
// 还原方法 deviceId() 可被静态分析沿组装链调出，也可用 Frida 直接观察。
// 真实写法：分片作为实例字段，单例模式，缓存计算结果。
public class PivotParts {
    // "pivot_" 的字节 ^ 0x3C
    private final int[] devA = {76, 85, 74, 83, 72, 99};
    // "device" 的字节 ^ 0x5A
    private final int[] devB = {62, 63, 44, 51, 57, 63};

    private volatile String cachedDeviceId;
    private volatile String cachedFingerprint;

    private static volatile PivotParts INSTANCE;

    private PivotParts() {}

    public static PivotParts getInstance() {
        if (INSTANCE == null) {
            synchronized (PivotParts.class) {
                if (INSTANCE == null) INSTANCE = new PivotParts();
            }
        }
        return INSTANCE;
    }

    /** 把异或分片还原成正确 deviceId；Frida 可直接调用观察。 */
    public String deviceId() {
        if (cachedDeviceId != null) return cachedDeviceId;
        String s = dec(devA, 0x3C) + dec(devB, 0x5A);
        cachedDeviceId = s;
        return s;
    }

    /** 还原结果的 MD5 指纹（与 Activity 中的提交校验一致）。 */
    public String fingerprint() {
        if (cachedFingerprint != null) return cachedFingerprint;
        String fp = md5Hex(deviceId());
        cachedFingerprint = fp;
        return fp;
    }

    private String md5Hex(String s) {
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

    private String dec(int[] a, int key) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ key);
        }
        return new String(out, StandardCharsets.UTF_8);
    }
}
