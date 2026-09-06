package com.fatdog.reverse;

/**
 * KKL3 断魂谷：JNI 桥——四路哨兵 + 静默投毒。
 *
 * nativeSign(page, ts) 才是取数签名入口：每次先跑哨兵，命中就把
 * HMAC 密钥永久翻 1 bit，服务端验签 403。nativeStatus 只做只读自检。
 */
public final class Kkl3Native {
    static { System.loadLibrary("kkl3"); }

    /** 只读哨兵自检详情（不投毒） */
    public static native String nativeStatus();

    /** 取数 HMAC 签名，内部执行哨兵并按需投毒 */
    public static native String nativeSign(int page, long ts);

    /** 当前进程密钥是否已被投毒 */
    public static native int nativePoisoned();

    private Kkl3Native() {}
}
