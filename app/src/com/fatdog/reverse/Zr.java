package com.fatdog.reverse;

// 关卡 31 的 JNI 桥：两截钥匙跨层拼装——前半 "Fatdog_" 在 Java（q.Ke，已被 R8 改名），
// 后半 "lonely" 在 libl31.so。Java 启动时把 Ke.class 递给 native 缓存成全局引用，
// 之后每次签名/加密 native 都回调 Ke.partA 取件：单看任何一侧都拿不到完整密钥。
public class Zr {
    static {
        System.loadLibrary("l31");
        bindKeyClass(com.fatdog.reverse.q.Ke.class);
    }

    private Zr() {
    }

    // 把持有另一半密钥的类交给 native（jclass 直传，绕开 FindClass 按名查找，不怕 R8 改名）
    private static native void bindKeyClass(Class<?> holder);

    // RC4(拼合密钥, "page=N&ts=T") 的 hex 形态
    public static native String nativeEnc(int page, long ts);

    // 对 encHex 做 HMAC-SHA256，返回 hex
    public static native String nativeSign(String encHex);
}
