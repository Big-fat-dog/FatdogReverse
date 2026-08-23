package com.fatdog.reverse;

// 天地秘境·流沙河的 JNI 桥：手写 AES-128 藏在 libm1.so 里。
// S 盒是标准的——认骨架足够；但轮常量 Rcon 被换过三处血，
// 标准 AES 库解不开它自己加密的密文。钥匙由标记运行时派生。
public class Tj {
    static {
        System.loadLibrary("m1");
    }

    private Tj() {
    }

    // 魔改 AES-128-ECB(钥匙, "page=N&ts=T" 零填充)
    public static native String nativeEnc(int page, long ts);

    // HMAC-SHA256(mac, enc)，mac 由标记运行时派生
    public static native String nativeSign(String enc);
}
