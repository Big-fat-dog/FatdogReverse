package com.fatdog.reverse;

/**
 * KL15 万法归宗：JNI 桥——多阶段谜题。
 * loadLibrary("m14")
 *
 * 四个独立入口，不再是简单的 guard→answer：
 *   computeA() → 阶段 A 种子值
 *   computeB(a) → 阶段 B（基于 A）
 *   computeC(a,b) → 阶段 C（组合 A+B）
 *   verify(a,b,c) → 三值全对返回 1
 */
public final class Am {
    static { System.loadLibrary("m14"); }

    /** 综合校验（兼容旧接口）：反调试+CRC，返回 1=通过, -1=反调试, -2=CRC */
    public static native int nativeGuard(int input);

    /** 阶段 A：XOR+移位+密钥异或 → 种子值 */
    public static native int nativeComputeA();

    /** 阶段 B：CRC32 衍生 + KX 混淆 */
    public static native int nativeComputeB(int a);

    /** 阶段 C：SHA256(a‖b) 取前 32 位 */
    public static native int nativeComputeC(int a, int b);

    /** 验证三值：全对返回 1，否则 0 */
    public static native int nativeVerify(int a, int b, int c);

    private Am() {}
}
