package com.fatdog.reverse;

/**
 * KL17 金蝉脱壳：JNI 桥——二代壳 DEX 热加载 + 反调试。
 * loadLibrary("k17")
 */
public final class Ek {
    static { System.loadLibrary("k17"); }

    /** 反调试三重检测 + 反hook，全部通过返回 1 */
    public static native int nativeAntiDebug();

    /** 解密后的明文 hex（反调试通过才有效） */
    public static native String nativeDecrypt();

    /** 提取的种子值（反调试通过才有效） */
    public static native int nativeSeed();

    /** 最终答案 hex（反调试通过才有效） */
    public static native String nativeAnswer();

    /** 反调试状态详情 */
    public static native String nativeStatus();

    private Ek() {}
}
