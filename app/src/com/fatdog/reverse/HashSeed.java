package com.fatdog.reverse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

// 关卡 10 的种子素材：正确口令被切成两段，分别用不同掩码异或存放。
// 还原时先按字节异或，再把两段按顺序拼起来；SHA-256 指纹只用于提交时校验。
public class HashSeed {
    // 第 1 段：^0x33
    private static final int[] A = {85, 65, 90, 87};
    // 第 2 段：^0x5A
    private static final int[] B = {59};

    private HashSeed() {}

    /** 把异或分片拼成正确口令；Frida 可调用此方法直接观察还原结果。 */
    public static String seed() {
        return dec(A, 0x33) + dec(B, 0x5A);
    }

    /** 完整种子的 SHA-256 指纹。 */
    public static String sha256Fingerprint() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(seed().getBytes(StandardCharsets.UTF_8));
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
