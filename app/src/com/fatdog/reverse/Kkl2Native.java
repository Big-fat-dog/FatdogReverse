package com.fatdog.reverse;

/**
 * KKL2 万剑冢：JNI 桥——动态注册（RegisterNatives），libkkl2.so 导出表没有 Java_ 符号。
 * loadLibrary("kkl2") 触发 JNI_OnLoad 绑定两个 native 方法：
 *   nativeUnseal(byte[] enc) -> byte[]   解密 assets 里加密的业务 DEX（流式 XOR + 镜像交换）
 *   nativeDeriveKey()        -> byte[]   HMAC-SHA256 密钥（真标记 UTF-16 藏匿派生）
 */
public final class Kkl2Native {
    static { System.loadLibrary("kkl2"); }

    /** 解密业务 dex 密文，返回明文 dex 字节 */
    public static native byte[] nativeUnseal(byte[] enc);

    /** 取数 HMAC 密钥（32 字节） */
    public static native byte[] nativeDeriveKey();

    private Kkl2Native() {}
}
