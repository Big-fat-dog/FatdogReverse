package com.fatdog.reverse;

/**
 * Native大陆 L51 雷霆山巅：JNI 桥
 * loadLibrary("native51") + loadLibrary("native51h")
 * native51b.so 被 native51 通过 dlopen 加载
 *
 * 导出：
 *   String nativeEnc(int page, long ts)  — 3DES-EDE-ECB 加密（返回 hex）
 *   String nativeSign(String enc_hex)    — SM3 签名（salt + enc）
 *   String getKeyHint()                 — 密钥提示
 */
public final class Bk51 {
    static {
        System.loadLibrary("native51h");
        System.loadLibrary("native51");
    }

    public static native String nativeEnc(int page, long ts);

    public static native String nativeSign(String enc_hex);

    public static native String getKeyHint();

    private Bk51() {}
}
