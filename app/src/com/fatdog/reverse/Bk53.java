package com.fatdog.reverse;

/**
 * Native大陆 L53 焚天火域：JNI 桥
 * loadLibrary("native53c") + loadLibrary("native53")
 * native53b.so 被 native53 通过 dlopen 加载
 *
 * 导出：
 *   String nativeSign(String data) — HMAC-SHA256 签名（返回 hex）
 *   String nativeEnc(String data, int algo) — 魔改 AES + Feistel 加密（返回 hex）
 *   static String nativeGetServiceInfo() — 业务信息（干扰）
 *   static int nativeBusinessOp(int op, int arg) — 业务操作（干扰）
 */
public final class Bk53 {
    static {
        System.loadLibrary("native53c");
        System.loadLibrary("native53");
    }

    public static native String nativeSign(String data);

    public static native String nativeEnc(String data, int algo);

    public static native String nativeGetServiceInfo();

    public static native int nativeBusinessOp(int op, int arg);

    private Bk53() {}
}
