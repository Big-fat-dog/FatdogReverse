package com.fatdog.reverse;

/**
 * KKL4 锁妖塔：JNI 桥——代码段 CRC 自校验 + 三点记账守卫。
 *
 * nativeOpen 建立记账状态；nativeSign 每次取数前核账并签 HMAC；
 * Java 每收到一页回调 nativeCommit，native 回调交叉核账后下一页才能签。
 */
public final class Kkl4Native {
    static { System.loadLibrary("kkl4"); }

    /** 开门记账；0 正常，负数表示守卫异常/已被投毒 */
    public static native int nativeOpen();

    /** 取数 HMAC 签名，内部执行 CRC + 记账守卫并按需投毒 */
    public static native String nativeSign(int page, long ts);

    /** 收到一页后回调核账；0 正常 */
    public static native int nativeCommit(int page, int count);

    /** 请求失败时撤销上一笔挂账 */
    public static native int nativeRollback();

    /** 只读自检，不判胜、不投毒 */
    public static native String nativeStatus();

    private Kkl4Native() {}
}
