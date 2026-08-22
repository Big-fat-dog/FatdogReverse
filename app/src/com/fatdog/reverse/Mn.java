package com.fatdog.reverse;

// 关卡 36 的 JNI 桥：手写 AES-128 藏在 libl36.so 底部，前面一堆诱饵变换函数。
// 钥匙藏法（不异或）：so 的 .rodata 里躺着一个 Base64 串——解码回来就是钥匙
// （Base64 不是加密）。mac 钥匙由标记运行时派生。
public class Mn {
    static {
        System.loadLibrary("l36");
    }

    private Mn() {
    }

    // AES-128-ECB(钥匙, "page=N&ts=T" 零填充)
    public static native String nativeEnc(int page, long ts);

    // HMAC-SHA256(mac, enc)
    public static native String nativeSign(String enc);
}
