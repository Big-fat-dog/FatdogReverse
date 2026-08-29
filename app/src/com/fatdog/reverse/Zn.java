package com.fatdog.reverse;

/**
 * KL14 偷天换日：JNI 桥——三 so 交叉验证。
 * loadLibrary("nebula") + loadLibrary("opera") + loadLibrary("plume")
 */
public final class Zn {
    static { System.loadLibrary("nebula"); System.loadLibrary("opera"); System.loadLibrary("plume"); }

    /** 跨 so 调用入口：a XOR b */
    public static native int nativeXor(int a, int b);

    /** libm13a：digest_A = XOR(SEED, 0xAA) */
    public static native int nativePartA();

    /** libm13a：交叉调用 libm13b，返回 digest_B 的整数值 */
    public static native int nativePartB();

    /** libm13b：digest_B = XOR(SEED, 0xBB)，通过 dlsym 调用 libm13a */
    public static native int nativePartBFromB();

    /** 拼装 A‖B → SHA-256 → hex[:32]，由 Java 传入 A/B */
    public static native String nativeCombine(int a, int b);

    /** libm13c：交叉调用 A+B → 最终答案（内部 dlsym） */
    public static native String nativeCombineFromC();

    private Zn() {}
}
