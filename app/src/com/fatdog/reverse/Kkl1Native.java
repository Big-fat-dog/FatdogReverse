package com.fatdog.reverse;

/**
 * KKL1 玄冥渊：JNI 桥——C++ vtable 派发 + 抽取回填。
 * loadLibrary("kkl1")
 */
public final class Kkl1Native {
    static { System.loadLibrary("kkl1"); }

    /** 解密后的明文 hex（供玩家观察抽取/解密结果） */
    public static native String nativeDecrypt();

    /** 提取的种子值 */
    public static native int nativeSeed();

    /** 最终答案 hex（SHA-256(seed)） */
    public static native String nativeAnswer();

    private Kkl1Native() {}
}
