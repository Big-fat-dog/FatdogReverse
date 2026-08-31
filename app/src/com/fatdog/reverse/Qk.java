package com.fatdog.reverse;

/**
 * 扶桑树 KL24 冰鉴悬镜：JNI 桥——进程状态双重校验（OR 判定）。
 * loadLibrary("ice")
 */
public final class Qk {
    static { System.loadLibrary("ice"); }

    /** TracerPid 子结果 */
    public static native int nativeTracerPid();

    /** 进程状态字子结果 */
    public static native int nativeState();

    /** 综合检测（OR 判定）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案 */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Qk() {}
}
