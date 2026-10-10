package com.fatdog.reverse;

/**
 * KKL3 断魂谷：JNI 桥。
 *
 * 本关的 native 侧不是单个 so，而是**五 so 编队**：只有其中一个导出 Java 符号，
 * 其余四个提供内核（在运行时按符号解析串起来）。少任何一个，取数入口都拿不到值，
 * 所以别只盯一个库看——先把编队成员摸齐。
 *
 * nativeSign(page, ts) 是全关唯一的取数入口：先过完整性守卫，再派生主钥，
 * 把 "page=N&ts=T" 用国密分组加密后连同摘要一起吐出，形如 "密文|签名"。
 */
public final class Kkl3Native {
    static {
        // 五 so 编队：加载顺序无关，缺一不可。
        System.loadLibrary("lattice");
        System.loadLibrary("basalt");
        System.loadLibrary("ingot");
        System.loadLibrary("harbor");
        System.loadLibrary("beacon");
    }

    /** 完整性自检详情（只读，不触发污染）。 */
    public static native String nativeStatus();

    /** 取数入口：返回 "密文|签名"；内核不齐或主钥已被污染时返回空串。 */
    public static native String nativeSign(int page, long ts);

    /** 当前进程主钥是否已被污染。 */
    public static native int nativePoisoned();

    private Kkl3Native() {}
}
