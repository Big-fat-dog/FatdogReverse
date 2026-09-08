package com.fatdog.reverse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

// Frida 关卡 4 的工具类之一：账号的 MD5 校验在这。
// 真实 App 写法：实例字段保存配置/密钥，实例方法做业务，单例或 DI 容器管理生命周期。
public class SignUtil {
    // md5Hex(accountSeed()) 的结果，留给玩家还原后对拍
    private static final String ACCOUNT_HASH = "c2fb08b69f270e9aae6e76438ec724a3";

    // "neon_" 的字节 ^ 0x3C
    private final int[] seedA = {82, 89, 83, 82, 99};
    // "user" 的字节 ^ 0x3C
    private final int[] seedB = {73, 79, 89, 78};

    private volatile String cachedSeed;
    private volatile String cachedFingerprint;

    /** 单例模式：真实项目常配合 Dagger/Hilt/Koin 等 DI 框架，这里简化为懒汉单例。 */
    private static volatile SignUtil INSTANCE;

    public static SignUtil getInstance() {
        if (INSTANCE == null) {
            synchronized (SignUtil.class) {
                if (INSTANCE == null) INSTANCE = new SignUtil();
            }
        }
        return INSTANCE;
    }

    /** 把异或分片还原成正确账号；Frida 可直接调用观察。 */
    public String accountSeed() {
        if (cachedSeed != null) return cachedSeed;
        String s = dec(seedA, 0x3C) + dec(seedB, 0x3C);
        cachedSeed = s;
        return s;
    }

    /** 还原结果的 MD5 指纹（与 Activity 中的提交校验一致）。 */
    public String fingerprint() {
        if (cachedFingerprint != null) return cachedFingerprint;
        String fp = md5Hex(accountSeed());
        cachedFingerprint = fp;
        return fp;
    }

    public boolean checkAccount(String account) {
        return md5Hex(account).equals(fingerprint());
    }

    /** 诱饵重载：Frida 训练点——overload 选择。直接 hook checkAccount 会命中双参数版本。 */
    public boolean checkAccount(String account, String salt) {
        return false;
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
