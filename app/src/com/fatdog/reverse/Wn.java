package com.fatdog.reverse;

// 签名校验对抗第三课「移形换影」：不再经过 PackageManager——
// native 直接打开 sourceDir，解析 zip 中央目录定位 META-INF/*.RSA，
// 手写 ASN.1 剥出 X.509 证书 DER，SHA-256 与基准比对。
// 对 getPackageInfo/SigningInfo/Signature 的任何 Hook 在本关全部失明。
// 记账守卫与 L44 同构：assertGuard 三连核账防整体替换。
public class Wn {
    static {
        System.loadLibrary("m7");
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

    public static void guard(int minTicks) {
        int rc = assertGuard(minTicks);
        if (rc != 0) throw new IllegalStateException("guard=" + rc);
    }
}
