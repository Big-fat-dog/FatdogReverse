package com.fatdog.reverse.kkl4;

/**
 * 锁妖塔 · 第八片：取数。
 *
 * 唯一声明 native 方法的业务片。本片被门面 so（citadel）通过
 * nativeBind(Class) 用 RegisterNatives 显式绑定——子 DexClassLoader
 * 不会自动解析父加载器的 so，不绑就是 UnsatisfiedLinkError。
 * 真正的密钥与算法全在 native 侧（VM 主钥 → AES-CTR + MD5）。
 */
public final class GateKeeper4h {
    private GateKeeper4h() {}

    /** 取数签名：返回 "enc|sign"（AES-128-CTR 密文 | MD5 摘要），失败返回空串。 */
    public static native String nativeSign(int page, long ts);
}
