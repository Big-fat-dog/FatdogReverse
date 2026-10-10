package com.fatdog.reverse;

/**
 * KKL5 诛仙台：JNI 桥——五 so 编队（门面 + 虚拟机 / 复合分组 / 摘要 / 守卫）。
 *
 * 五个 so 首尾相扣，门面用 dlsym 串联其余四个内核；缺一即取数失败。
 * onCreate 被"抽成 native"：门禁由一台自造的**内存机虚拟机**从真标记派生主钥
 * 后得出，字节码密文自反馈加密、静态段无明文（对齐 360 加固 native onCreate 还原）。
 * 取数走两层加密复合（内层分组 + 外层流式）+ 纯 MD5 摘要签名，密钥全部由 VM 派生。
 */
public final class Kkl5Native {
    static {
        System.loadLibrary("spindle");   // 门面
        System.loadLibrary("vellum");    // 内存机虚拟机内核
        System.loadLibrary("nimbus");    // 复合分组原语（内层分组 + 外层流式）
        System.loadLibrary("tallow");    // MD5
        System.loadLibrary("wraith");    // 完整性守卫
    }

    private Kkl5Native() {}

    /** onCreate 门禁：返回 "OK:..." 或 "FAIL:..."。 */
    public static native String nativeOnCreate(Object activity);

    /** 取数签名：返回 "enc|sign"（复合密文 | MD5 摘要），失败返回空串。 */
    public static native String nativeSign(int page, long ts);

    /** 复合解密：assets 业务 DEX 与服务端响应共用同一把派生主钥。 */
    public static native byte[] nativeUnseal(byte[] sealed);

    /** 只读自检：报告五 so 在位情况 + 守卫命中项 + 主钥状态，不判胜、不投毒。 */
    public static native String nativeStatus();

    /** 主钥是否已被守卫投毒（1 = 已污染）。 */
    public static native int nativePoisoned();
}
