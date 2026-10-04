package com.fatdog.reverse;

/**
 * Native大陆 L50 幽暗深渊：JNI 桥
 *
 * 导出：
 *   String nativeEnc(int page, long ts)  — AES-128-ECB 加密（返回 hex）
 *   String nativeSign(String enc_hex)    — SHA-256 签名
 *   String getKeyHint()                 — 密钥提示
 */
public final class Bk50 {

    public static native String nativeEnc(int page, long ts);

    public static native String nativeSign(String enc_hex);

    public static native String getKeyHint();

    public static native String nativeLadder(int a0);  // ibex
    public static native String nativeWrap(String a0);  // koala
    public static native String nativeFade(String a0, int a1);  // mink
    public static native String nativeChirp(int a0, long a1);  // cricket
    public static native String nativeSettle(String a0);  // invoice
    public static native String nativeBundle(String a0);  // parcel
    public static native int nativeQuote(String a0, int a1);  // vendor
    public static native String nativeIndex(String a0);  // manifest
    public static native String nativeStratum(int a0);  // granite

    private Bk50() {}
}
