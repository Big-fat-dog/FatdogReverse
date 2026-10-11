package com.fatdog.reverse;

/**
 * KKL3 断魂谷：JNI 桥。
 *
 * 本关的 native 侧是**四 so 编队**（门面 beacon + 国密 basalt + 摘要 ingot + 守卫 harbor），
 * 只有一个导出 Java 符号，其余按符号解析串起来，缺一不可。
 *
 * 主钥不在 native 里派生——它由业务片（3e 的 GateKeeper3.derive）在 Java 侧算出，
 * 再作为参数交给 nativeSign；native 只负责国密加密 + 摘要 + 守卫。
 *
 * 多 DEX 装载：
 *   nativeFold(enc, shard)   SM4 解密一片桩化 dex 字节
 *   nativeRebind(stub, bin)  把抽取 bin 里的真实方法体覆盖回桩化 dex（回填）
 */
public final class Kkl3Native {
    static {
        System.loadLibrary("basalt");
        System.loadLibrary("ingot");
        System.loadLibrary("harbor");
        System.loadLibrary("beacon");
    }

    /** 完整性自检详情（只读，不触发污染）。 */
    public static native String nativeStatus();

    /** 取数入口：seed 为业务片派生的 16B 主钥，返回 "密文|签名"。 */
    public static native String nativeSign(byte[] seed, int page, long ts);

    /** 解密一片桩化 dex（SM4-ECB）。 */
    public static native byte[] nativeFold(byte[] enc, int shard);

    /** 回填：把抽取 bin 的真实方法体覆盖回桩化 dex。 */
    public static native byte[] nativeRebind(byte[] stubDex, byte[] extractBin);

    /** 当前进程主钥是否已被污染。 */
    public static native int nativePoisoned();

    private Kkl3Native() {}
}
