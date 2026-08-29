package com.fatdog.reverse;

/**
 * KL20 太玄终章：JNI 桥——反调试 + 保护。
 * loadLibrary("delta")
 */
public final class Hk {
    static { System.loadLibrary("delta"); }

    /** 反调试检测 */
    public static native int nativeAntiDebug();

    /** 解密后的明文 hex */
    public static native String nativeDecrypt();

    /** 提取的种子值 */
    public static native int nativeSeed();

    /** 最终答案 hex（SHA-256(seed)） */
    public static native String nativeAnswer();

    private Hk() {}
}
