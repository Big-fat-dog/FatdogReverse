package com.fatdog.reverse;

/**
 * KKL2 万剑冢：JNI 桥——动态注册（RegisterNatives），libkkl2.so 导出表没有 Java_ 符号。
 * loadLibrary("kkl2") 触发 JNI_OnLoad 绑定两个 native 方法：
 *   nativeUnseal(byte[] enc) -> byte[]   解密 assets 里的业务 DEX 密文
 *                                        （AES-128-CBC → 去 PKCS7 → 镜像交换）
 *   nativeDeriveSeal()        -> byte[]   取数签名 seal（16B，MD5 派生）
 */
public final class Kkl2Native {
    static { System.loadLibrary("kkl2"); }

    /** 解密业务 dex 密文（AES-128-CBC），返回明文 dex 字节 */
    public static native byte[] nativeUnseal(byte[] enc);

    /** 取数签名 seal（16 字节，MD5 派生） */
    public static native byte[] nativeDeriveSeal();

    private Kkl2Native() {}
}
