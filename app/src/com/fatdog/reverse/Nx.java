package com.fatdog.reverse;

// 关卡 25 的 JNI 桥：verifyServer / nativeSign 的真身在 libnative.so（app/jni/native.c）。
// Java 里只有这两行声明——jadx 只能看到声明，逻辑与密钥全在 native 里。
public class Nx {
    static {
        System.loadLibrary("native");
    }

    // HTTPS 前的主机门禁：真身在 C 里（白名单 10.0.2.2 / 127.0.0.1 / localhost）。
    public static native int verifyServer(String host);

    // HMAC-SHA256 签名全在 C 里算（密钥 fatdemo_jni_2026 明文躺在 native.c）。
    // Java 层 Hook Mac/MessageDigest 看不到任何东西——签名根本不经过 Java。
    public static native String nativeSign(int page, long ts);
}
