package com.fatdog.reverse.kkl3;

/**
 * 断魂谷 · 明文诱饵（不进业务链，形似而质空）。
 *
 * 一个同名同形的壳，主钥派生用的是另一组假标记，
 * 派出的主钥服务端一律不认（403）。
 */
public final class GateKeeper3x {
    private GateKeeper3x() {}

    public static String magic() {
        return "vale";
    }

    /** 假标记码元：与真标记只差最后几位。 */
    public static char[] glyph() {
        return new char[]{'m', 'Z', '7', '~', 'q', 'B', '3', '#', 'n', 'V', '9', '!'};
    }

    public static byte[] derive() {
        char[] glyph = glyph();
        byte[] brine = "|kkl3_valley".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] out = new byte[16];
        for (int i = 0; i < 16; i++) {
            int mi = glyph[i % glyph.length] & 0xFF;
            int si = brine[i % brine.length] & 0xFF;
            int x = (mi * 0x3D + si * 0x29 + i * 0x1B) & 0xFF;
            x ^= (si << 2) & 0xFF;
            x = ((x >> 3) | (x << 5)) & 0xFF;
            x ^= mi ^ (i & 0x7F);
            out[i] = (byte) (x & 0xFF);
        }
        return out;
    }
}
