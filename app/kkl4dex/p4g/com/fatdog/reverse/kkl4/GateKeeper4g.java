package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 第七片：摘要。
 *
 * 把总数摘要成 32 位十六进制串（教学用，答案校验用）。
 * 依赖第六片的文本形态。
 */
public final class GateKeeper4g {
    private GateKeeper4g() {}

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** 对总数文本做 MD5，返回 32 位小写 hex。 */
    public static String digest(long sum) {
        try {
            byte[] in = GateKeeper4f.sumText(sum).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] d = md.digest(in);
            char[] out = new char[d.length * 2];
            for (int i = 0; i < d.length; i++) {
                out[i * 2] = HEX[(d[i] >> 4) & 0xF];
                out[i * 2 + 1] = HEX[d[i] & 0xF];
            }
            return new String(out);
        } catch (Exception e) {
            return "";
        }
    }
}
