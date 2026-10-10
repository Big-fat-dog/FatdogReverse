package com.fatdog.reverse;

/**
 * KKL1 玄冥渊：JNI 桥——静态导出（Java_com_fatdog_reverse_Kkl1Native_* 直接可见）。
 * loadLibrary("kkl1") 触发两个 native 方法：
 *   nativeUnseal(byte[] enc) -> byte[]   解密 assets 里整体加密的业务 DEX（base64 + RC4）
 *   nativeDeriveSeal()        -> byte[]   取数签名用的 seal（16 字节，真标记 MD5 派生）
 */
public final class Kkl1Native {
    static { System.loadLibrary("kkl1"); }

    /** 解密业务 dex 密文（base64 文本），返回明文 dex 字节 */
    public static native byte[] nativeUnseal(byte[] enc);

    /** 取数签名 seal（16 字节） */
    public static native byte[] nativeDeriveSeal();

    private Kkl1Native() {}
}
