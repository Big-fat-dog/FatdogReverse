package com.fatdog.reverse;

// 天地秘境·流沙河的 JNI 桥：手写 RC4 藏在 libm4.so 里，两层魔改——
// KSA 的初始 S 盒不是恒等置换而是自定义表；PRGA 输出后再过 16 字节循环掩码。
// 标准 RC4 解不开它自己加密的密文。钥匙由标记运行时派生。
public class Vr {
    static {
        System.loadLibrary("m4");
    }

    private Vr() {
    }

    // 魔改 RC4(钥匙, "page=N&ts=T" 零填充)
    public static native String nativeEnc(int page, long ts);

    // HMAC-SHA256(mac, enc)，mac 由标记运行时派生
    public static native String nativeSign(String enc);
}
