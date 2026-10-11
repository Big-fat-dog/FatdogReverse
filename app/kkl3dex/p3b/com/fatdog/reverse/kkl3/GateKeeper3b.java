package com.fatdog.reverse.kkl3;

/**
 * 断魂谷 · 第二片：形状。
 *
 * 只管一件事：确认拿到的 16 个字节是不是对的模样。
 * 盐字串也放在这里，与 3a 的码元一道进派生。
 */
public final class GateKeeper3b {
    private GateKeeper3b() {}

    /** 形状校验：16 字节、非全零即算过关（教学性校验，不参与密钥）。 */
    public static boolean markLooksValid(byte[] seed) {
        if (seed == null || seed.length != 16) return false;
        boolean any = false;
        for (byte b : seed) {
            if (b != 0) { any = true; break; }
        }
        return any;
    }

    /** 盐字串（ASCII），与 3a 的码元拼起来派生主钥。 */
    public static byte[] brine() {
        return "|kkl3_valley".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }
}
