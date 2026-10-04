package com.fatdog.reverse;

/**
 * 扶桑树 KL26 暮霭沉沉：JNI 桥——6 路评分阈值制 + 加载期检测。
 * loadLibrary("dusk")
 */
public final class Sk {
    static { System.loadLibrary("dusk"); }

    /** ① timing 侧信道子结果 */
    public static native int nativeTiming();

    /** ② Frida 版本/特征嗅探子结果 */
    public static native int nativeVersion();

    /** ③ 可执行段私有脏页（smaps Private_Dirty） */
    public static native int nativeSmapsDirty();

    /** ④ 无名可执行映射（可疑代码岛） */
    public static native int nativeAnonExec();

    /** ⑤ ARM64 跳板扫描 */
    public static native int nativeTrampoline();

    /** ⑥ libc 关键函数入口 内存 vs 磁盘比对 */
    public static native int nativeLibcPrologue();

    /** 加载期(.init_array)检测相位 → 0=未执行 1=加载期干净 2=加载期已命中 */
    public static native int nativeLoadPhase();

    /** 综合检测（评分阈值制，命中 ≥2 判检出）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案（加载期已命中则永久锁定） */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Sk() {}
}
