package com.fatdog.reverse;

/**
 * Native大陆 L48 落日平原：JNI 桥
 *
 * 导出：
 *   String nativeSign(int page, long ts)  — HMAC-SHA256 签名
 *   String getKeyHint()                  — 密钥右半段提示
 */
public final class Bk48 {

    public static native String nativeSign(int page, long ts);

    public static native String getKeyHint();

    public static native String nativeAudit();  // heron
    public static native String nativeDigest(String a0);  // pelican
    public static native String nativeToken(int a0);  // magpie
    public static native String nativeChecksum(String a0);  // walrus
    public static native String nativePad(String a0, int a1);  // beetle
    public static native String nativeEnvelope(int a0, long a1);  // ledger
    public static native String nativeSeal(String a0);  // voucher
    public static native int nativeRate(int a0, int a1);  // tariff
    public static native String nativeBlend(String a0);  // cobalt

    private Bk48() {}
}
