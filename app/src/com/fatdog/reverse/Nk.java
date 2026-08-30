package com.fatdog.reverse;

/**
 * 扶桑树 KL22 落影寻痕：JNI 桥——/proc/self/fd 扫描 + maps 搜索。
 * loadLibrary("owl")
 */
public final class Nk {
    static { System.loadLibrary("owl"); }

    /** 综合检测（fd+maps，OR 判定）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** fd 扫描子结果 */
    public static native int nativeFdScan();

    /** maps 搜索子结果 */
    public static native int nativeMapsScan();

    /** 最终答案 */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Nk() {}
}
