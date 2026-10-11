package com.fatdog.reverse;

/**
 * KKL4 锁妖塔：JNI 桥——五 so 编队（门面 + 虚拟机 / 分组 / 摘要 / 守卫）。
 *
 * 五个 so 首尾相扣，门面用 dlsym 串联其余四个内核；缺一即取数失败。
 * 主钥（32B）由一台自造的**栈式虚拟机**从真标记派生，字节码链式加密、静态段无明文。
 */
public final class Kkl4Native {
    static {
        System.loadLibrary("citadel");    // 门面
        System.loadLibrary("obsidian");   // 虚拟机内核
        System.loadLibrary("cavern");     // AES-128-CTR
        System.loadLibrary("tundra");     // MD5
        System.loadLibrary("prowl");      // 完整性守卫
    }

    /** 只读自检：报告五 so 在位情况 + 守卫命中项 + 主钥状态，不判胜、不投毒 */
    public static native String nativeStatus();

    /** 取数签名：返回 "enc|sign"（AES-128-CTR 密文 | MD5 摘要），失败返回空串 */
    public static native String nativeSign(int page, long ts);

    /** 主钥是否已被守卫投毒（1 = 已污染） */
    public static native int nativePoisoned();

    /** 多类壳解密：layer 1=壳层 w.*，layer 2=业务 4a..4i（shard 0..8）。
     *  密钥由 VM 主钥域分离派生，先过 VM 才有钥匙。 */
    public static native byte[] nativeFold(byte[] enc, int layer, int shard);

    /** 把业务 DEX 里的 GateKeeper4h.nativeSign 显式绑定（RegisterNatives）。
     *  返回 1=成功，0=失败。 */
    public static native int nativeBind(Class<?> target);

    private Kkl4Native() {}
}
