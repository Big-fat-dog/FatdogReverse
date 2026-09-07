package com.fatdog.reverse;

/**
 * Native大陆 L52 冰封雪域：JNI 桥
 * loadLibrary("native52k") + loadLibrary("native52")
 * native52b.so 被 native52 通过 dlopen 加载
 *
 * 导出：
 *   String nativeEnc(String data)  — 魔改 SM4 加密（返回 hex）
 *   String nativeSign(int page, int ts) — HMAC-SHA256 签名（返回 hex）
 *   static String nativeRc4Decrypt(String data) — RC4 解密（native52k 导出）
 */
public final class Bk52 {
    static {
        System.loadLibrary("native52k");
        System.loadLibrary("native52");
    }

    public static native String nativeEnc(String data);

    public static native String nativeSign(int page, int ts);

    public static native String nativeRc4Decrypt(String data);

    private Bk52() {}
}
