package com.fatdog.reverse;

// 关卡 35 的 JNI 桥：libl35.so 里手写了两套密码（3DES + SM4），文件前半是
// 一堆无用变换函数，真身经函数指针表派发。密钥不异或——由 UTF-16 标记
// Fatdog_sneak 运行时派生。认算法靠魔数：DES 的 S1 盒、SM4 的 d6 90 e9 fe。
public class Ir {
    static {
        System.loadLibrary("l35");
    }

    private Ir() {
    }

    // SM4-ECB(Fatdog_sneak 派生钥, "page=N&ts=T" 零填充)
    public static native String nativeEncSm4(int page, long ts);

    // 3DES-EDE(派生钥, 大端 ts 的 8 字节)
    public static native String nativeEncDes(long ts);

    // HMAC-SHA256(master, e1 + "|" + e2)
    public static native String nativeSign(String e1, String e2);
}
