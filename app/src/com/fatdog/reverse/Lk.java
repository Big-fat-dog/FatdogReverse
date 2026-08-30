package com.fatdog.reverse;

/**
 * 扶桑树 KL21 枯叶听风：JNI 桥——端口探测 + D-Bus 协议指纹。
 * loadLibrary("fox")
 */
public final class Lk {
    static { System.loadLibrary("fox"); }

    /** 综合检测（端口+D-Bus，OR 判定）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 端口探测子结果 */
    public static native int nativePortScan();

    /** D-Bus 指纹子结果 */
    public static native int nativeDbusFingerprint();

    /** 最终答案（不受检测结果影响） */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Lk() {}
}
