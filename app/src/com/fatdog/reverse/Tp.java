package com.fatdog.reverse;

// 天地秘境·流沙河的 JNI 桥：手写 DES 藏在 libm2.so 里。
// 骨架可认——S1 开头 14,04,0d,01；但 IP 排列表首尾互换、FP 同步重算、
// S3 盒两值换位，标准 DES 库解不开它自己加密的密文。钥匙由标记运行时派生。
public class Tp {
    static {
        System.loadLibrary("frost");
    }

    private Tp() {
    }

    // 魔改 3DES-EDE(钥匙, "page=N&ts=T" 零填充)
    public static native String nativeEncDes(int page, long ts);

    // HMAC-SHA256(mac, enc)，mac 由标记运行时派生
    public static native String nativeSign(String enc);
}
