package com.fatdog.reverse;

// 签名校验对抗第二课：摘要计算与记账全部下沉 native。
// Java 只递证书 DER 字节；SHA-256、基准比对、verdict、ticks 全在 libm6.so 内部——
// hook Java 层 MessageDigest 出口彻底失效；
// 整体替换 passCert/assertGuard 会因 ticks 踏步被 assertGuard 当场抓包。
// HMAC 密钥前半仍按惯例异或藏匿，后半在 Xh。
public class Wk {
    static {
        System.loadLibrary("m6");
    }

    private Wk() {
    }

    // "Fatdog_" ^0x3C
    static final int[] KA = {122, 93, 72, 88, 83, 91, 99};

    public static String hmacKey() {
        StringBuilder sb = new StringBuilder(KA.length);
        for (int v : KA) sb.append((char) (v ^ 0x3C));
        return sb.toString() + Xh.decode(Xh.KB, 0x5A);
    }

    /** 递入证书 DER：native 内记账(ticks++)、摘要、比对基准 */
    public static native void passCert(byte[] der);

    /** 三连核账：0=放行 / -1=未校验 / -2=ticks 踏步 / -3=verdict 假 */
    public static native int assertGuard(int minTicks);

    /** Java 包装：非 0 直接抛，业务层自行决定提示方式（本关选择静默拦截请求） */
    public static void guard(int minTicks) {
        int rc = assertGuard(minTicks);
        if (rc != 0) throw new IllegalStateException("guard=" + rc);
    }
}
