package com.fatdog.reverse;

/**
 * 天机阁 KL29 暗流涌动（TLV 二进制协议）：JNI 桥——OR 判定。
 * loadLibrary("tide")
 */
public final class Ak29 {
    static { System.loadLibrary("tide"); }

    /** TLV magic 子结果 */
    public static native int nativeTlvMagic();

    /** ptrace 子结果 */
    public static native int nativePtrace();

    /** 综合检测（OR 判定）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案 */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Ak29() {}
}
