package com.fatdog.reverse;

// 关卡 37 的 JNI 桥：手写 SHA-256 变体——K 表与压缩轮和教科书一致，
// 但初始 IV 整组换成了派生值；摘要出来再过一层 RC4 才是最终签名。
// hashlib 对不上不是 bug，是"雪崩"本身。
public class Qa {
    static {
        System.loadLibrary("wyvern");
    }

    private Qa() {
    }

    // RC4(派生钥, SHA256变体("page=N&ts=T"))
    public static native String nativeSign(int page, long ts);
}
