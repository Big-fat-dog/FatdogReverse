package com.fatdog.reverse;

/**
 * 扶桑树 KL25 暮雾锁听：JNI 桥——内存/线程/结构层 5 路评分阈值制 + 加载期检测。
 * loadLibrary("mist")
 */
public final class Rk {
    static { System.loadLibrary("mist"); }

    /** ① maps frida 特征子结果 */
    public static native int nativeMapsFrida();

    /** ② 线程指纹子结果（gum-js-loop/pool-frida 等 Frida 专属线程名） */
    public static native int nativeThreadFinger();

    /** ③ auxv/ELF 一致性子结果（1=一致；评分时不一致才记分） */
    public static native int nativeAuxvHook();

    /** ④ 线程数一致性子结果（status Threads vs /proc/self/task 目录数，1=异常） */
    public static native int nativeThreadCountCheck();

    /** ⑤ maps 幻影映射子结果（r-x 段含 memfd:/(deleted)，1=命中） */
    public static native int nativeMapsPhantom();

    /** 加载期(.init_array)检测相位 → 0=未执行 1=加载期干净 2=加载期已命中 */
    public static native int nativeLoadPhase();

    /** 综合检测（评分阈值制，命中 ≥2 判检出）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案（加载期已命中则永久锁定） */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Rk() {}
}
