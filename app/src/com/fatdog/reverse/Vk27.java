package com.fatdog.reverse;

/**
 * 扶桑树 KL27 轻纱覆影：JNI 桥——OR 判定。
 * loadLibrary("veil")
 */
public final class Vk27 {
    static { System.loadLibrary("veil"); }

    /** 线程上下文子结果 */
    public static native int nativeThreadContext();

    /** 时序交叉子结果 */
    public static native int nativeTimingCrossref();

    /** 综合检测（OR 判定）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案 */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Vk27() {}
}
