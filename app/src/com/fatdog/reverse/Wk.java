package com.fatdog.reverse;

// 签名校验对抗第二课：摘要计算与记账全部下沉 native。
// Java 只递证书 DER 字节；SHA-256、基准比对、verdict、ticks 全在 libpearl.so 内部——
// hook Java 层 MessageDigest 出口彻底失效；
// 整体替换 passCert/assertGuard 会因 ticks 踏步被 assertGuard 当场抓包。
// HMAC 密钥前半仍按惯例异或藏匿，后半在 Xh。
//
// 2026-10-02 双层链路：
//   ① nativeVerdictToken 内含一个纯开关常量（g_door）——出厂关着，门不开就取不到数。
//      开门必须改 so 一个字节 → 必然重打包重签 → 触发 ②。
//   ② auditCode() 就是 assertGuard(1) 的结论；非 0 时客户端改用诱饵钥签名，
//      服务端据此回喂脏数据（不再 403）——把"被检测到"藏成一个需要自己察觉的信号。
public class Wk {
    static {
        System.loadLibrary("pearl");
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

    /** ② 校验结论（供客户端决定用真标记还是诱饵标记签名） */
    public static int auditCode() {
        return assertGuard(1);
    }

    /** ③ 取数令牌：门未开返回空串（取不到数）；门已开返回 16 位 hex 一次性令牌 */
    public static native String nativeVerdictToken();

    public static String verdictToken() {
        String t = nativeVerdictToken();
        return t == null ? "" : t;
    }
}
