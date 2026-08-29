package com.fatdog.reverse;

/**
 * KL19 虚空造化：JNI 桥——VMP 虚拟机保护。
 * loadLibrary("bison")
 */
public final class Gk {
    static { System.loadLibrary("bison"); }

    /** 解密后的字节码 hex */
    public static native String nativeDecrypt();

    /** 提取的种子值 */
    public static native int nativeSeed();

    /** 最终答案 hex（SHA-256(seed)）*/
    public static native String nativeAnswer();

    /** VM 执行结果 */
    public static native int nativeVmExecute();

    /** 直接计算（去掉 VM），供对拍验证 */
    public static native int nativeDirect(int seed);

    private Gk() {}
}
