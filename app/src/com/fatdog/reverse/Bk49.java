package com.fatdog.reverse;

/**
 * Native大陆 L49 迷雾森林：JNI 桥
 * loadLibrary("native49")
 *
 * 导出：
 *   String nativeEnc(int page, long ts)  — SM4-ECB 加密（返回 hex）
 *   String nativeSign(String enc_hex)    — HMAC-SHA256 签名
 *   String getKeyHint()                 — 密钥提示
 */
public final class Bk49 {
    static { System.loadLibrary("native49"); }

    public static native String nativeEnc(int page, long ts);

    public static native String nativeSign(String enc_hex);

    public static native String getKeyHint();

    private Bk49() {}
}
