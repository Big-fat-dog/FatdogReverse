package com.fatdog.reverse;

/**
 * Native大陆 L52 冰封雪域：JNI 桥
 * registry.so 被 moose 通过 dlopen 加载
 *
 * 导出：
 *   String nativeEnc(String data)  — 魔改 SM4 加密（返回 hex）
 *   String nativeSign(int page, int ts) — HMAC-SHA256 签名（返回 hex）
 *   static String nativeRc4Decrypt(String data) — RC4 解密（cobra 导出）
 */
public final class Bk52 {

    public static native String nativeEnc(String data);

    public static native String nativeSign(int page, int ts);

    public static native String nativeRc4Decrypt(String data);

    public static native String nativeCatalog(String a0);  // registry
    public static native String nativeProwl(int a0);  // dingo
    public static native String nativeSoar(String a0);  // eagle
    public static native String nativeTrill(int a0, long a1);  // finch
    public static native int nativeMarkup(String a0, int a1);  // retail
    public static native String nativeLedger(String a0);  // banking
    public static native String nativePool(String a0);  // fund
    public static native String nativeBid(int a0, int a1);  // tender

    private Bk52() {}
}
