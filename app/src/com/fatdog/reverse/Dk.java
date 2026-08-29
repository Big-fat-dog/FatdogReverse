package com.fatdog.reverse;

/**
 * KL16 破壳新生：JNI 桥——一代壳 DEX 静态加密。
 * loadLibrary("taupe")
 */
public final class Dk {
    static { System.loadLibrary("taupe"); }

    /** 解密后的明文 hex（供玩家观察解密结果） */
    public static native String nativeDecrypt();

    /** 提取的种子值 */
    public static native int nativeSeed();

    /** 最终答案 hex（SHA-256(seed)） */
    public static native String nativeAnswer();

    private Dk() {}
}
