package com.fatdog.reverse;

/**
 * Native大陆 L49 迷雾森林：JNI 桥
 *
 * 导出：
 *   String nativeEnc(int page, long ts)  — SM4-ECB 加密（返回 hex）
 *   String nativeSign(String enc_hex)    — HMAC-SHA256 签名
 *   String getKeyHint()                 — 密钥提示
 */
public final class Bk49 {

    public static native String nativeEnc(int page, long ts);

    public static native String nativeSign(String enc_hex);

    public static native String getKeyHint();

    public static native String nativeProbe();  // falcon
    public static native String nativeMix(String a0);  // gecko
    public static native String nativeFingerprint(int a0);  // lynx
    public static native String nativeStretch(String a0, int a1);  // hornet
    public static native long nativeAdvance(int a0, int a1);  // payroll
    public static native String nativeRoute(String a0);  // dispatch
    public static native String nativePack(String a0);  // cargo
    public static native String nativeHold(String a0, int a1);  // escrow
    public static native String nativeLattice(String a0);  // quartz

    private Bk49() {}
}
