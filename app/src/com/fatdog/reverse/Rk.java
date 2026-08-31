package com.fatdog.reverse;

/**
 * 扶桑树 KL25 暮雾锁听：JNI 桥——三重检测 NAND 判定。
 * loadLibrary("mist")
 */
public final class Rk {
    static { System.loadLibrary("mist"); }

    /** maps frida 特征子结果 */
    public static native int nativeMapsFrida();

    /** open hook 子结果 */
    public static native int nativeOpenHook();

    /** auxv hook 子结果 */
    public static native int nativeAuxvHook();

    /** 综合检测（NAND 判定）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案 */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Rk() {}
}
