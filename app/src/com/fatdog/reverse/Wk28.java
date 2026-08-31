package com.fatdog.reverse;

/**
 * 扶桑树 KL28 雪落无痕：JNI 桥——OR 判定。
 * loadLibrary("snow")
 */
public final class Wk28 {
    static { System.loadLibrary("snow"); }

    /** signal handler 子结果 */
    public static native int nativeSignal();

    /** ptrace 子结果 */
    public static native int nativePtrace();

    /** 综合检测（OR 判定）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案 */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Wk28() {}
}
