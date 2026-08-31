package com.fatdog.reverse;

/**
 * 扶桑树 KL26 暮霭沉沉：JNI 桥——XOR 判定。
 * loadLibrary("dusk")
 */
public final class Sk {
    static { System.loadLibrary("dusk"); }

    /** timing 子结果 */
    public static native int nativeTiming();

    /** 版本嗅探子结果 */
    public static native int nativeVersion();

    /** 综合检测（XOR 判定）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案 */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Sk() {}
}
