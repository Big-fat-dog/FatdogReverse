package com.fatdog.reverse;

/**
 * Native大陆 L50 幽暗深渊：JNI 桥
 * loadLibrary("native50")
 *
 * 导出：
 *   String nativeEnc(int page, long ts)  — AES-128-ECB 加密（返回 hex）
 *   String nativeSign(String enc_hex)    — SHA-256 签名
 *   String getKeyHint()                 — 密钥提示
 */
public final class Bk50 {
    static { System.loadLibrary("native50"); }

    public static native String nativeEnc(int page, long ts);

    public static native String nativeSign(String enc_hex);

    public static native String getKeyHint();

    private Bk50() {}
}
