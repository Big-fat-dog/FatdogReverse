package com.fatdog.reverse;

/**
 * KKL1 玄冥渊 —— JNI 桥。
 *
 * 导出表里没有 Java_ 符号：下面两个 native 由 libkkl1.so 的 JNI_OnLoad
 * 经 RegisterNatives 动态注册（静态翻符号表只会看到一个加载入口）。
 *   nativeFold(byte[] enc) -> byte[]   还原一段整体加密的业务分片（落盘前调用）
 *   nativeSeed()           -> byte[]   取数签名用的 mark（16 字节，字面翻不出来）
 */
public final class Kkl1Native {
    static { System.loadLibrary("kkl1"); }

    /** 还原一段加密分片：密文文本 →（文本解码 + 流还原）→ 明文 dex 字节 */
    public static native byte[] nativeFold(byte[] enc);

    /** 取数签名用的 mark（16 字节） */
    public static native byte[] nativeSeed();

    private Kkl1Native() {}
}
