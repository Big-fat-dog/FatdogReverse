package com.fatdog.reverse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

// Frida 关卡 4 的工具类之一：账号的 MD5 校验在这。
// 名字故意取成 SignUtil——教程里最常见的"签名工具类"名，让人以为它很普通。
// 账号明文不再是"外部知识"：两段异或分片就放在本类，MD5 只做指纹校验。
public class SignUtil {
    // md5Hex(accountSeed()) 的结果，留给玩家还原后对拍
    static final String ACCOUNT_HASH = "c2fb08b69f270e9aae6e76438ec724a3";

    // "neon_" 的字节 ^ 0x3C
    private static final int[] SEED_A = {82, 89, 83, 82, 99};
    // "user" 的字节 ^ 0x3C
    private static final int[] SEED_B = {73, 79, 89, 78};

    private SignUtil() {}

    /** 把异或分片还原成正确账号；Frida 可直接调用观察。 */
    public static String accountSeed() {
        return dec(SEED_A, 0x3C) + dec(SEED_B, 0x3C);
    }

    /** 还原结果的 MD5 指纹（与 Activity 中的提交校验一致）。 */
    public static String fingerprint() {
        return md5Hex(accountSeed());
    }

    static boolean checkAccount(String account) {
        return md5Hex(account).equals(fingerprint());
    }

    /** 诱饵重载：Frida 训练点——overload 选择。直接 hook checkAccount 会命中双参数版本。 */
    static boolean checkAccount(String account, String salt) {
        return false;
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
