package com.fatdog.reverse;

// 关卡 30 的 JNI 桥：libl30.so 里四个同形签名函数经函数指针表间接派发，
// 密钥全部以 UTF-16 码元（\x 十六进制字面值）存放——strings 默认一无所获。
public class Vn {
    static {
        System.loadLibrary("l30");
    }

    // HMAC-SHA256 签名全在 C 里算——但四个候选里只有一个是真身
    public static native String nativeSign(int page, long ts);
}
