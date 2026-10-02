package com.fatdog.reverse;

// 签名校验对抗第三课「移形换影」：不再经过 PackageManager——
// native 直接打开 sourceDir，解析 zip 中央目录定位 META-INF/*.RSA，
// 手写 ASN.1 剥出 X.509 证书 DER，SHA-256 与基准比对。
// 对 getPackageInfo/SigningInfo/Signature 的任何 Hook 在本关全部失明。
// 记账守卫与 L44 同构：assertGuard 三连核账防整体替换。
//
// 2026-10-02 双层链路：① 层在 Java 侧（关不掉的弹窗 + gateOpen 恒假，见 u45Activity）；
//   ② auditCode() 是 assertGuard(1) 的结论——非 0 时客户端改用诱饵钥签名，服务端回脏数据；
//   ③ nativeVerdictToken() 产出一次性令牌 vt。
public class Wn {
    static {
        System.loadLibrary("coral");
    }

    private Wn() {
    }

    // "Fatdog_" ^0x3C
    static final int[] KA = {122, 93, 72, 88, 83, 91, 99};

    public static String hmacKey() {
        StringBuilder sb = new StringBuilder(KA.length);
        for (int v : KA) sb.append((char) (v ^ 0x3C));
        return sb.toString() + Yb.decode(Yb.KB, 0x5A);
    }

    /** 递入安装文件路径：native 自读 APK、找签名块、剥证书、摘要比对、记账 */
    public static native void passApkPath(String sourceDir);

    /** 三连核账：0=放行 / -1=未校验 / -2=ticks 踏步 / -3=verdict 假 */
    public static native int assertGuard(int minTicks);

    /** ② 校验结论（供客户端决定用真标记还是诱饵标记签名） */
    public static int auditCode() {
        return assertGuard(1);
    }

    /** ③ 取数令牌：16 位 hex 一次性令牌（服务端按 key = SHA256(标记‖vt) 派生验签密钥） */
    public static native String nativeVerdictToken();

    public static String verdictToken() {
        String t = nativeVerdictToken();
        return t == null ? "" : t;
    }
}
