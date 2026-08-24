package com.fatdog.reverse;

// 天地秘境·流沙河的 JNI 桥：手写 SM4 藏在 libm3.so 里。
// FK 与 S 盒都是标准的——认骨架足够；但轮常量 CK 的最后 8 个值
// 被换过血，标准 SM4 解不开它自己加密的密文。钥匙由标记运行时派生。
public class Uq {
    static {
        System.loadLibrary("m3");
    }

    private Uq() {
    }

    // 魔改 SM4-ECB(钥匙, "page=N&ts=T" 零填充)
    public static native String nativeEnc(int page, long ts);

    // HMAC-SHA256(mac, enc)，mac 由标记运行时派生
    public static native String nativeSign(String enc);
}
