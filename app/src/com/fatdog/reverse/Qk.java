package com.fatdog.reverse;

/**
 * 扶桑树 KL24 冰鉴悬镜：JNI 桥——进程状态层 4 路评分阈值制 + 加载期检测。
 * loadLibrary("ice")
 */
public final class Qk {
    static { System.loadLibrary("ice"); }

    /** ① TracerPid 子结果 */
    public static native int nativeTracerPid();

    /** ② 进程状态字子结果 */
    public static native int nativeState();

    /** ③ 父进程链子结果（PPid cmdline 命中调试器名） */
    public static native int nativePpidChain();

    /** ④ status 结构完整性子结果（被喂假/过滤 → 1） */
    public static native int nativeStatusIntegrity();

    /** 加载期(.init_array)检测相位 → 0=未执行 1=加载期干净 2=加载期已命中 */
    public static native int nativeLoadPhase();

    /** 综合检测（评分阈值制，命中 ≥2 判检出）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案（加载期已命中则永久锁定） */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Qk() {}
}
