package com.fatdog.reverse;

/**
 * KL41 纸上谈兵（须弥界 · JS Bundle 基础）
 * JNI 桥类：loadLibrary("jar")
 *
 * 动态注册：nativeSign / nativeDecoySign / nativeVerify / nativeAnswer / nativeDetectDebug
 *
 * 标记：Fatdog_tactic（真）/ Fatdog_plan（诱饵）
 */
public class RnBridge {
    static {
        System.loadLibrary("jar");
    }

    private RnBridge() {}

    public static native String nativeSign(int page, long ts);
    public static native String nativeDecoySign(int page, long ts);
    public static native boolean nativeVerify(int page, long ts, String sign);
    public static native String nativeAnswer();
    public static native boolean nativeDetectDebug();
}
