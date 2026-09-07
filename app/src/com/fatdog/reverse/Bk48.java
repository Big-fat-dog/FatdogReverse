package com.fatdog.reverse;

/**
 * Native大陆 L48 落日平原：JNI 桥
 * loadLibrary("native48")
 *
 * 导出：
 *   String nativeSign(int page, long ts)  — HMAC-SHA256 签名
 *   String getKeyHint()                  — 密钥右半段提示
 */
public final class Bk48 {
    static { System.loadLibrary("native48"); }

    public static native String nativeSign(int page, long ts);

    public static native String getKeyHint();

    private Bk48() {}
}
