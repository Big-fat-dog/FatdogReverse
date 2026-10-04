package com.fatdog.reverse;

/**
 * Native大陆 L51 雷霆山巅：JNI 桥
 * quota.so 被 shark 通过 dlopen 加载
 *
 * 导出：
 *   String nativeEnc(int page, long ts)  — 3DES-EDE-ECB 加密（返回 hex）
 *   String nativeSign(String enc_hex)    — SM3 签名（salt + enc）
 *   String getKeyHint()                 — 密钥提示
 */
public final class Bk51 {

    public static native String nativeEnc(int page, long ts);

    public static native String nativeSign(String enc_hex);

    public static native String getKeyHint();

    public static native String nativeBucket(int a0);  // quota
    public static native String nativeShed(String a0);  // newt
    public static native String nativeSlink(String a0, int a1);  // weasel
    public static native String nativeLeap(int a0);  // salmon
    public static native String nativeReconcile(String a0);  // audit
    public static native String nativeHaul(String a0, int a1);  // freight
    public static native String nativeRelay(String a0);  // courier
    public static native int nativeCoupon(int a0, int a1);  // bond

    private Bk51() {}
}
