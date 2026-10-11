package com.fatdog.reverse.kkl5;

/**
 * 诛仙台 · 业务片 5l —— native 取数声明。
 *
 * 这个 native 方法不在此 DEX 里实现：它由门面 so（libspindle.so）在装载本片时
 * 用 RegisterNatives 显式绑定——子 DexClassLoader 不会自动解析父加载器的 so，
 * 不绑即 UnsatisfiedLinkError。这是「VMP × 多类壳」咬合点的 Java 侧锚。
 */
public final class GateKeeper5l {

    private GateKeeper5l() {}

    /** 取数签名：返回 "enc|sign"，失败返回空串。实现由 nativeBind 注入。 */
    public static native String nativeSign(int page, long ts);
}
