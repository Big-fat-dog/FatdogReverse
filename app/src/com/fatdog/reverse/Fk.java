package com.fatdog.reverse;

/**
 * KL18 乾坤迷阵：JNI 桥——OLLVM 控制流平坦化。
 * loadLibrary("blaze")
 */
public final class Fk {
    static { System.loadLibrary("blaze"); }

    /** 解密后的明文 hex */
    public static native String nativeDecrypt();

    /** 提取的种子值 */
    public static native int nativeSeed();

    /** 最终答案 hex（SHA-256(seed)） */
    public static native String nativeAnswer();

    /** OLLVM 状态机执行（暴露状态机路径） */
    public static native int nativeOllvm(int seed);

    /** 原始算法（去 OLLVM，供对拍验证） */
    public static native int nativeCore(int seed);

    private Fk() {}
}
