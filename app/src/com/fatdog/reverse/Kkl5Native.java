package com.fatdog.reverse;

/**
 * KKL5 诛仙台 JNI 桥。
 *
 * onCreate 被"抽成 native"：Activity 的 onCreate 里不实现任何门禁逻辑，
 * 真正判断在 libkkl5.so 的 VMP 解释器里执行（对齐 360 加固 native onCreate 还原手法）。
 * 取数签名走 AES-128-CBC + HMAC-SHA256，密钥全部由 VM 从真标记派生。
 */
public final class Kkl5Native {
    static {
        System.loadLibrary("c++_shared");
        System.loadLibrary("kkl5");
    }

    private Kkl5Native() {}

    /** onCreate 门禁：返回 "OK:..." 或 "FAIL:..."。 */
    public static native String nativeOnCreate(Object activity);

    /** 开门记账；0 成功，负数表示守卫触发/投毒。 */
    public static native int nativeOpen();

    /** 返回 "encHex|signHex"；encHex = hex(IV || AES-128-CBC(page=N&ts=T))。 */
    public static native String nativeSign(int page, long ts);

    public static native int nativeCommit(int page, int nums);

    public static native void nativeRollback();

    public static native String nativeStatus();

    /** 校验服务端响应签名：HMAC(mac_key, "page|ts|iv|d")。 */
    public static native boolean nativeVerifyResponse(int page, long ts, String iv, String d, String sign);

    /** 解密 assets/kkl5 的加密 DEX，返回内存 DEX 字节。 */
    public static native byte[] nativeUnseal(byte[] sealed);
}
