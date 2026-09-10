package com.fatdog.reverse;

/**
 * 扶桑树 KL23 照妖显形：JNI 桥——内存指纹三重校验（AND 判定）。
 * loadLibrary("sun")
 */
public final class Ok {
    static { System.loadLibrary("sun"); }

    /** 综合检测（三路条件全部成立才检出）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** maps hex pattern 子结果 */
    public static native int nativeMapsHex();

    /** 运行时 DT_DEBUG 校验子结果 */
    public static native int nativeDtDebug();

    /** auxv/ELF 一致性子结果 */
    public static native int nativeAuxv();

    /** 最终答案 */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Ok() {}
}
