package com.fatdog.reverse;

/**
 * 扶桑树 KL28 雪落无痕：JNI 桥——8 路评分阈值制 + 加载期检测（C++ OOP 实现）。
 * loadLibrary("snow")
 */
public final class Wk28 {
    static { System.loadLibrary("snow"); }

    /** ① 信号试点自检（SIGUSR1 handler 预装查询 + 自触发可复现性） */
    public static native int nativeSignal();

    /** ② TracerPid 追踪检查 */
    public static native int nativePtrace();

    /** ③ 可执行段私有脏页（smaps Private_Dirty） */
    public static native int nativeSmapsDirty();

    /** ④ 无名可执行映射（可疑代码岛） */
    public static native int nativeAnonExec();

    /** ⑤ ARM64 跳板扫描 */
    public static native int nativeTrampoline();

    /** ⑥ libc 关键函数入口 内存 vs 磁盘比对 */
    public static native int nativeLibcPrologue();

    /** ⑦ libc 代码段多点采样校验（抓非入口补丁） */
    public static native int nativeLibcScan();

    /** ⑧ libc 符号解析完整性（抓 LD_PRELOAD / GOT 换库） */
    public static native int nativeLibcGot();

    /** 加载期(.init_array)检测相位 → 0=未执行 1=加载期干净 2=加载期已命中 */
    public static native int nativeLoadPhase();

    /** 综合检测（评分阈值制，命中 ≥2 判检出）→ 0=安全 1=检出 */
    public static native int nativeFridaDetect();

    /** 最终答案（加载期已命中则永久锁定） */
    public static native String nativeAnswer();

    /** 检测详情 */
    public static native String nativeStatus();

    private Wk28() {}
}
